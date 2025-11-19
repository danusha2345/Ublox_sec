use std::env;
use std::fs::{self, File};
use std::path::Path;
use std::collections::HashMap;
use std::error::Error;

use rayon::prelude::*;
use colored::*;
use rand::Rng;
use num_bigint::{BigInt, Sign};
use num_traits::{Num, One, Zero};
use plotters::prelude::*;

// =========================================================
// 1. КОНФИГУРАЦИЯ
// =========================================================
const UBX_SYNC_1: u8 = 0xB5;
const UBX_SYNC_2: u8 = 0x62;
const CLASS_SEC: u8 = 0x27; // Класс сообщений безопасности u-blox
const SIG_LEN: usize = 64;  // Длина подписи (32 байта R + 32 байта S)

// Порядок группы кривой secp256r1 (NIST P-256)
const SECP256R1_ORDER_HEX: &str = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";

// =========================================================
// 2. СТРУКТУРЫ ДАННЫХ
// =========================================================

#[derive(Clone)]
struct SignatureData {
    r: BigInt,
    s: BigInt,
    r_bytes: Vec<u8>,
    s_bytes: Vec<u8>,
    full_payload: Vec<u8>, // Сохраняем payload для экспорта (чтобы SageMath мог найти хеш)
    packet_idx: usize,
}

/// Статистика для графиков
struct CryptoStats {
    r_buckets: [u64; 100],      // Гистограмма R (0..100%)
    s_buckets: [u64; 100],      // Гистограмма S (0..100%)
    bit_counts: Vec<u64>,       // Подсчет единиц для каждого бита (Bit Bias)
    byte_counts: [u64; 256],    // Частота встречаемости байтов (0..255)
    total_count: u64,
    high_s_count: u64,          // Счетчик High-S (уязвимость Malleability)
    zero_val_count: u64,        // Счетчик R=0 или S=0 (фатальная ошибка)
}

impl CryptoStats {
    fn new() -> Self {
        Self {
            r_buckets: [0; 100],
            s_buckets: [0; 100],
            bit_counts: vec![0; SIG_LEN * 8],
            byte_counts: [0; 256],
            total_count: 0,
            high_s_count: 0,
            zero_val_count: 0,
        }
    }

    // Объединение статистики от разных потоков
    fn merge(&mut self, other: &CryptoStats) {
        for i in 0..100 {
            self.r_buckets[i] += other.r_buckets[i];
            self.s_buckets[i] += other.s_buckets[i];
        }
        for i in 0..self.bit_counts.len() {
            self.bit_counts[i] += other.bit_counts[i];
        }
        for i in 0..256 {
            self.byte_counts[i] += other.byte_counts[i];
        }
        self.total_count += other.total_count;
        self.high_s_count += other.high_s_count;
        self.zero_val_count += other.zero_val_count;
    }

    fn process(&mut self, sig: &SignatureData, order_half: &BigInt) {
        self.total_count += 1;

        // Проверки безопасности
        if sig.r.is_zero() || sig.s.is_zero() { self.zero_val_count += 1; }
        if &sig.s > order_half { self.high_s_count += 1; }

        // Распределение величин (для поиска Bias)
        let r_top = extract_top_u64(&sig.r);
        let s_top = extract_top_u64(&sig.s);
        
        // Нормализуем к диапазону 0..99
        let r_idx = (r_top as u128 * 100 / u64::MAX as u128) as usize;
        let s_idx = (s_top as u128 * 100 / u64::MAX as u128) as usize;
        
        if r_idx < 100 { self.r_buckets[r_idx] += 1; }
        if s_idx < 100 { self.s_buckets[s_idx] += 1; }

        // Битовый и Байтовый анализ
        let full_bytes = [&sig.r_bytes[..], &sig.s_bytes[..]].concat();
        for (byte_idx, &byte) in full_bytes.iter().enumerate() {
            self.byte_counts[byte as usize] += 1;
            for bit_idx in 0..8 {
                // Проверяем бит (слева направо)
                if (byte >> (7 - bit_idx)) & 1 == 1 {
                    if byte_idx * 8 + bit_idx < self.bit_counts.len() {
                        self.bit_counts[byte_idx * 8 + bit_idx] += 1;
                    }
                }
            }
        }
    }
}

// Вспомогательная функция для получения "верхушки" большого числа (для гистограммы)
fn extract_top_u64(val: &BigInt) -> u64 {
    let bytes = val.to_bytes_be().1;
    if bytes.len() < 8 { return 0; }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[0..8]);
    u64::from_be_bytes(buf)
}

// Структура для экспорта в CSV (для SageMath)
#[derive(serde::Serialize)]
struct CaptureRow {
    packet_idx: usize,
    r_hex: String,
    s_hex: String,
    full_payload_hex: String,
}

// =========================================================
// 3. MAIN
// =========================================================

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    
    println!("{}", "=================================================".green());
    println!("{}", "   U-BLOX ECDSA AUDIT TOOL v1.0 (Final)          ".green().bold());
    println!("{}", "=================================================".green());

    // 1. Загрузка данных
    let raw_data: Vec<u8>;
    if args.len() > 1 {
        let path = &args[1];
        println!("Чтение файла: {}", path);
        raw_data = fs::read(Path::new(path)).expect("Не удалось прочитать файл");
    } else {
        println!("{}", "Файл не указан. Запуск в режиме СИМУЛЯЦИИ (Bad RNG).".yellow());
        println!("Для анализа реального файла: cargo run --release -- <путь_к_логу.ubx>");
        raw_data = generate_dummy_data(5000, true);
    }

    // 2. Парсинг
    println!("Поиск пакетов UBX-SEC...");
    let signatures = extract_signatures(&raw_data);
    if signatures.is_empty() {
        println!("{}", "Подписи не найдены. Проверьте формат файла.".red());
        return Ok(());
    }
    println!("Найдено подписей: {}", signatures.len().to_string().cyan().bold());

    // 3. Анализ
    println!("Запуск многопоточного анализа...");
    let order = BigInt::from_str_radix(SECP256R1_ORDER_HEX, 16).unwrap();
    let order_half = &order / 2;

    let stats = signatures.par_iter()
        .fold(CryptoStats::new, |mut acc, sig| {
            acc.process(sig, &order_half);
            acc
        })
        .reduce(CryptoStats::new, |mut a, b| {
            a.merge(&b);
            a
        });

    // 4. Генерация графиков (PNG)
    println!("Генерация графиков...");
    save_plots(&stats)?;
    println!("{}", "Графики сохранены в папку 'plots/'".green());

    // 5. Проверка критических уязвимостей
    println!("Проверка на повторение Nonce (Sony Attack)...");
    check_duplicates(&signatures);

    // 6. Экспорт данных
    println!("Экспорт данных для Lattice Attack...");
    save_csv(&signatures)?;
    println!("{}", "Данные сохранены в 'hnp_capture.csv'".green());

    Ok(())
}

// =========================================================
// 4. ПАРСЕР UBX
// =========================================================

fn extract_signatures(data: &[u8]) -> Vec<SignatureData> {
    let mut sigs = Vec::new();
    let mut i = 0;
    let mut packet_idx = 0;

    while i + 6 < data.len() {
        // Ищем заголовок B5 62
        if data[i] == UBX_SYNC_1 && data[i+1] == UBX_SYNC_2 {
            let cls = data[i+2];
            let len = ((data[i+5] as usize) << 8) | (data[i+4] as usize);
            
            // Проверка на выход за границы массива
            if i + 6 + len + 2 > data.len() { break; }

            // Если это класс SEC (0x27) и длина похожа на наличие подписи
            if cls == CLASS_SEC && len >= SIG_LEN {
                let payload_start = i + 6;
                let payload = &data[payload_start..payload_start+len];

                // Эвристика: Подпись (64 байта) обычно находится в самом конце payload
                let sig_start = len - SIG_LEN;
                
                let r_bytes = payload[sig_start..sig_start+32].to_vec();
                let s_bytes = payload[sig_start+32..sig_start+64].to_vec();

                sigs.push(SignatureData {
                    r: BigInt::from_bytes_be(Sign::Plus, &r_bytes),
                    s: BigInt::from_bytes_be(Sign::Plus, &s_bytes),
                    r_bytes,
                    s_bytes,
                    full_payload: payload.to_vec(),
                    packet_idx,
                });
            }

            packet_idx += 1;
            i += 6 + len + 2; // Переход к следующему пакету
        } else {
            i += 1;
        }
    }
    sigs
}

// =========================================================
// 5. ГРАФИКА И ЭКСПОРТ
// =========================================================

fn save_plots(stats: &CryptoStats) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all("plots")?;

    // График распределения R
    draw_chart(
        "plots/distribution_r.png", 
        "Nonce Distribution (R) - Should be Flat", 
        &stats.r_buckets, &RED
    )?;

    // График распределения S
    draw_chart(
        "plots/distribution_s.png", 
        "Signature Distribution (S) - Should be Flat", 
        &stats.s_buckets, &BLUE
    )?;

    // График Bit Bias
    draw_bit_bias(
        "plots/bit_bias.png", 
        "Bit Bias (Ideal = 0.5)", 
        &stats.bit_counts, stats.total_count
    )?;

    // График Байтов
    draw_byte_hist(
        "plots/byte_hist.png", 
        "Byte Frequency (0-255)", 
        &stats.byte_counts
    )?;

    Ok(())
}

// Рисует линейный график распределения
fn draw_chart(filename: &str, title: &str, buckets: &[u64], color: &RGBColor) -> Result<(), Box<dyn Error>> {
    let root = BitMapBackend::new(filename, (1024, 600)).into_drawing_area();
    root.fill(&WHITE)?;
    
    let max_val = *buckets.iter().max().unwrap_or(&1);

    let mut chart = ChartBuilder::on(&root)
        .caption(title, ("sans-serif", 30).into_font())
        .margin(20)
        .x_label_area_size(40)
        .y_label_area_size(60)
        .build_cartesian_2d(0u32..100u32, 0u64..(max_val + max_val/10))?;

    chart.configure_mesh().draw()?;
    chart.draw_series(LineSeries::new(
        buckets.iter().enumerate().map(|(i, &c)| (i as u32, c)),
        color,
    ))?;

    root.present()?;
    Ok(())
}

// Рисует график Bit Bias
fn draw_bit_bias(filename: &str, title: &str, counts: &[u64], total: u64) -> Result<(), Box<dyn Error>> {
    let root = BitMapBackend::new(filename, (1200, 600)).into_drawing_area();
    root.fill(&WHITE)?;

    let mut chart = ChartBuilder::on(&root)
        .caption(title, ("sans-serif", 30).into_font())
        .margin(20)
        .x_label_area_size(40)
        .y_label_area_size(60)
        .build_cartesian_2d(0u32..(counts.len() as u32), 0.0f64..1.0f64)?;

    chart.configure_mesh()
        .y_desc("Probability of '1'")
        .draw()?;

    // Идеальная линия 0.5
    chart.draw_series(LineSeries::new(
        (0..counts.len()).map(|x| (x as u32, 0.5)),
        &GREEN,
    ))?;

    // Точки
    chart.draw_series(PointSeries::of_element(
        counts.iter().enumerate().map(|(i, &c)| (i as u32, c as f64 / total as f64)),
        2,
        &BLUE,
        &|c, s, st| {
            let color = if (c.1 - 0.5).abs() > 0.1 { &RED } else { &BLUE };
            return EmptyElement::at(c) + Circle::new((0,0), s, color.filled());
        },
    ))?;

    root.present()?;
    Ok(())
}

// Рисует гистограмму байтов
fn draw_byte_hist(filename: &str, title: &str, counts: &[u64]) -> Result<(), Box<dyn Error>> {
    let root = BitMapBackend::new(filename, (1024, 600)).into_drawing_area();
    root.fill(&WHITE)?;
    let max_val = *counts.iter().max().unwrap_or(&1);

    let mut chart = ChartBuilder::on(&root)
        .caption(title, ("sans-serif", 30).into_font())
        .margin(20)
        .x_label_area_size(40)
        .y_label_area_size(60)
        .build_cartesian_2d(0u32..256u32, 0u64..(max_val + max_val/10))?;

    chart.configure_mesh().draw()?;
    chart.draw_series(
        Histogram::vertical(&chart)
            .style(BLUE.filled())
            .data(counts.iter().enumerate().map(|(i, &c)| (i as u32, c))),
    )?;

    root.present()?;
    Ok(())
}

fn save_csv(signatures: &[SignatureData]) -> Result<(), Box<dyn Error>> {
    let mut wtr = csv::Writer::from_path("hnp_capture.csv")?;
    for sig in signatures {
        wtr.serialize(CaptureRow {
            packet_idx: sig.packet_idx,
            r_hex: hex::encode(&sig.r_bytes),
            s_hex: hex::encode(&sig.s_bytes),
            full_payload_hex: hex::encode(&sig.full_payload),
        })?;
    }
    wtr.flush()?;
    Ok(())
}

// Проверка на дубликаты R
fn check_duplicates(signatures: &[SignatureData]) {
    let mut r_map: HashMap<Vec<u8>, Vec<&SignatureData>> = HashMap::new();
    for sig in signatures {
        r_map.entry(sig.r_bytes.clone()).or_default().push(sig);
    }

    let mut found = false;
    for (_, sigs) in r_map {
        if sigs.len() > 1 {
            // Проверка, что это разные подписи (S отличается), но R одинаковый
            if sigs[0].s != sigs[1].s {
                println!("{}", "!!! КРИТИЧЕСКАЯ УЯЗВИМОСТЬ: НАЙДЕН ДУБЛИКАТ R !!!".red().bold().blink());
                println!("Packet Index 1: {}", sigs[0].packet_idx);
                println!("Packet Index 2: {}", sigs[1].packet_idx);
                println!("R: {}", hex::encode(&sigs[0].r_bytes));
                found = true;
                break;
            }
        }
    }
    if !found {
        println!("{}", "Дубликатов Nonce не обнаружено.".green());
    }
}

// Генератор фейковых данных для теста
fn generate_dummy_data(count: usize, bad_rng: bool) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut rng = rand::thread_rng();

    for _ in 0..count {
        // Header UBX-SEC
        buf.extend_from_slice(&[0xB5, 0x62, 0x27, 0x01, 0x48, 0x00]); 
        for _ in 0..8 { buf.push(0); }
        
        for _ in 0..64 {
            if bad_rng {
                // Симуляция "Колокола" (Bias)
                let v1: u8 = rng.gen();
                let v2: u8 = rng.gen();
                buf.push((v1/2).wrapping_add(v2/2));
            } else {
                buf.push(rng.gen());
            }
        }
        buf.push(0); buf.push(0);
    }
    buf
}
