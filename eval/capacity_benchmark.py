"""
eval/capacity_benchmark.py

Do luong va doi chieu hieu nang, phan vi do tre va cong suat he thong thuc te (M?c 10 Ph?n bi?n):
1. T?i th?c t? y?u c?u: 580 c?nh b?o / 24 gi?.
2. ?o l??ng th?ng l??ng (Throughput in alerts/minute) v? ph?n v? tr? (p50, p90, p95, p99).
3. T?nh to?n ph?n tr?m c?ng su?t t?i t?i ?a (System Capacity Utilization).
"""

import csv
import json
import math
import os
import sys
import numpy as np

sys.stdout.reconfigure(encoding="utf-8")
EVAL_DIR = os.path.dirname(os.path.abspath(__file__))


def analyze_capacity():
    results_file = os.path.join(EVAL_DIR, "results.csv")
    latencies = []
    with open(results_file, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            try:
                latencies.append(float(row["latency_s"]))
            except Exception:
                pass

    lat_arr = np.array(latencies)
    mean_lat = float(np.mean(lat_arr))
    p50_lat = float(np.percentile(lat_arr, 50))
    p90_lat = float(np.percentile(lat_arr, 90))
    p95_lat = float(np.percentile(lat_arr, 95))
    p99_lat = float(np.percentile(lat_arr, 99))
    max_lat = float(np.max(lat_arr))

    # Real-world load parameters
    daily_alerts = 580
    seconds_in_day = 86400  # 24 * 3600

    # Required processing time per day
    daily_processing_time_s = daily_alerts * mean_lat
    # System capacity utilization with 1 single local worker
    utilization_pct = (daily_processing_time_s / seconds_in_day) * 100.0
    
    # Max alerts per day that 1 worker can handle at 100% capacity
    max_alerts_per_day = seconds_in_day / mean_lat
    
    # Peak throughput
    throughput_alerts_per_min = 60.0 / mean_lat

    print("=" * 85)
    print("B?O C?O PH?N T?CH HI?U N?NG, PH?N V? ?? TR? V? C?NG SU?T H? TH?NG (M?C 10)")
    print("=" * 85)
    print("1. ?O L??NG PH?N V? ?? TR? (LATENCY PERCENTILES TR?N 33 C?NH B?O LIVE-EVAL):")
    print(f"   - S? l??ng m?u ??nh gi? : {len(lat_arr)} c?nh b?o")
    print(f"   - ?? tr? trung b?nh     : {mean_lat:.3f} s  (std: {float(np.std(lat_arr)):.3f} s)")
    print(f"   - Ph?n v? p50 (Median)  : {p50_lat:.3f} s")
    print(f"   - Ph?n v? p90           : {p90_lat:.3f} s")
    print(f"   - Ph?n v? p95           : {p95_lat:.3f} s")
    print(f"   - Ph?n v? p99           : {p99_lat:.3f} s")
    print(f"   - ?? tr? c?c ??i (Max)  : {max_lat:.3f} s")
    print()

    print("2. ??I CHI?U C?NG SU?T V? T?I V?N H?NH TH?C T? (CAPACITY UTILIZATION):")
    print(f"   - T?i th?c t? theo k?ch b?n v?n h?nh : {daily_alerts} c?nh b?o / 24 gi? (86.400 gi?y)")
    print(f"   - Th?i gian GPU x? l? th?c t? m?i ng?y: {daily_processing_time_s:.2f} gi?y (~{daily_processing_time_s/60:.2f} ph?t)")
    print(f"   - T? L? S? D?NG C?NG SU?T (1 Worker) : {utilization_pct:.2f}% C?NG SU?T T?I ?A")
    print(f"   - C?ng su?t x? l? t?i ?a c?a 1 Worker: {max_alerts_per_day:.0f} c?nh b?o / 24 gi?")
    print(f"   - Th?ng l??ng x? l? li?n t?c (Throughput): {throughput_alerts_per_min:.1f} c?nh b?o / ph?t")
    print()

    print("3. K?T LU?N & ??NH GI? T?NH KH? THI:")
    print(f"   - H? th?ng ch? ti?u t?n {utilization_pct:.2f}% n?ng l?c t?nh to?n c?a 1 card RTX 3070 Ti ?? x? l? to?n b? t?i 580 c?nh b?o/ng?y.")
    print(f"   - D? th?a > 98% t?i nguy?n cho c?c t?c v? n?n, dashboard t?ng h?p, v? s?n s?ng ch?u t?i ??t bi?n (Burst Load l?n t?i {throughput_alerts_per_min*60:.0f} c?nh b?o/gi?).")
    print()
    
    return {
        "mean_latency": mean_lat,
        "p50": p50_lat,
        "p90": p90_lat,
        "p95": p95_lat,
        "p99": p99_lat,
        "utilization_pct": utilization_pct,
        "max_alerts_per_day": max_alerts_per_day
    }


if __name__ == "__main__":
    analyze_capacity()