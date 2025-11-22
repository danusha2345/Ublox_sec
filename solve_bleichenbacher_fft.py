#!/usr/bin/env python3
"""
Анализ смещения (Bias) в подписях ECDSA с использованием FFT (Fast Fourier Transform).
Генерация графиков спектра.
"""

import csv
import numpy as np
import matplotlib.pyplot as plt
from scipy.fft import fft, fftfreq
import os

def load_signatures(filename):
    r_list = []
    s_list = []
    with open(filename, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                r_list.append(int(row['r']))
                s_list.append(int(row['s']))
            except ValueError:
                continue
    return r_list, s_list

def analyze_and_plot_fft(values, name, filename_suffix, n_bins=256):
    """
    Анализ FFT и построение графика
    """
    print(f"\n--- Анализ и построение графика для {name} ---")
    
    # Берем старшие 8 бит
    msb_values = []
    for v in values:
        shift = max(0, v.bit_length() - 8)
        msb = v >> shift
        msb_values.append(msb)
        
    # Гистограмма
    hist, bins = np.histogram(msb_values, bins=n_bins, range=(0, n_bins))
    hist_norm = hist - np.mean(hist)
    
    # FFT
    yf = fft(hist_norm)
    xf = fftfreq(n_bins, 1)[:n_bins//2]
    power = 2.0/n_bins * np.abs(yf[0:n_bins//2])
    
    # Построение графика
    plt.figure(figsize=(10, 6))
    plt.plot(xf, power, color='blue', linewidth=1.5)
    plt.title(f'FFT Spectrum Analysis: {name}', fontsize=14)
    plt.xlabel('Frequency', fontsize=12)
    plt.ylabel('Power (Spectral Density)', fontsize=12)
    plt.grid(True, alpha=0.3)
    
    # Добавляем порог шума (3 sigma)
    std_dev = np.std(power)
    threshold = 3 * std_dev
    plt.axhline(y=threshold, color='red', linestyle='--', label=f'Noise Threshold (3σ = {threshold:.2f})')
    
    # Отмечаем пики
    peak_idx = np.argmax(power)
    plt.plot(xf[peak_idx], power[peak_idx], 'ro')
    plt.annotate(f'Max Peak: {power[peak_idx]:.2f}', 
                 xy=(xf[peak_idx], power[peak_idx]), 
                 xytext=(xf[peak_idx]+0.05, power[peak_idx]),
                 arrowprops=dict(facecolor='black', shrink=0.05))
    
    plt.legend()
    
    # Вывод пиков
    indices = np.argsort(power)[::-1]
    print(f"Top 3 Peaks for {name}:")
    for i in range(3):
        idx = indices[i]
        print(f"  Freq: {xf[idx]:.4f}, Power: {power[idx]:.4f} (Threshold: {threshold:.4f})")
        
    # Сохранение
    output_file = f'plots/fft_spectrum_{filename_suffix}.png'
    plt.savefig(output_file, dpi=150)
    print(f"График сохранен в {output_file}")
    plt.close()

def main():
    print("Загрузка подписей...")
    filename = 'sigs_combined.csv' if os.path.exists('sigs_combined.csv') else 'sigs_new.csv'
    print(f"Используем файл: {filename}")
    r_vals, s_vals = load_signatures(filename)
    
    # Создаем папку для графиков если нужно
    if not os.path.exists('plots'):
        os.makedirs('plots')
    
    analyze_and_plot_fft(r_vals, "Nonce R (MSB Distribution)", "r")
    analyze_and_plot_fft(s_vals, "Signature S (MSB Distribution)", "s")
    
    print("\nГотово! Проверьте созданные PNG файлы.")

if __name__ == "__main__":
    main()
