#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path
import numpy as np
import pandas as pd

# -----------------------------
# Costanti e mapping colonne
# -----------------------------
DEFAULT_PROTOCOLS = ["modbus", "dnp3", "mqtt", "ethernet-ip"]
DEFAULT_SWITCHES = ["s1", "s2"]
# SOLO 128, 192 e 256
DEFAULT_CONFIGS = [
    ("128", "128_resources.csv"),
    ("192", "192_resources.csv"),
    ("256", "256_resources.csv"),
]

METRIC_MAP = {
    "cpu": "CPU_Total (%)",
    "mem": "Memory_Total (MB)",
    "power": "Voltage (V)",
}

SUMMARY_COLS = [
    "Protocol", "Switch", "Config",
    "CPU_Min", "CPU_Max", "CPU_Mean", "CPU_Std",
    "Mem_Min", "Mem_Max", "Mem_Mean", "Mem_Std",
    "Power_Min", "Power_Max", "Power_Mean", "Power_Std",
]

# -----------------------------
# Helper I/O & stats
# -----------------------------
def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

def find_column(df, expected_label):
    cols = {c.strip(): c for c in df.columns}
    if expected_label in cols:
        return cols[expected_label]
    exp = expected_label.lower().replace(" ", "").replace("_", "")
    for c in df.columns:
        k = c.lower().replace(" ", "").replace("_", "")
        if exp == k:
            return c
    keybits = [b for b in expected_label.lower().split() if b not in {"(", ")", "%"}]
    for c in df.columns:
        lc = c.lower()
        if all(b in lc for b in keybits):
            return c
    raise KeyError(f"Column '{expected_label}' not found. Available: {list(df.columns)}")

def load_and_clean_csv(path, cores):
    df = pd.read_csv(path, skipinitialspace=True)
    cpu_col = find_column(df, METRIC_MAP["cpu"])
    mem_col = find_column(df, METRIC_MAP["mem"])
    power_col = find_column(df, METRIC_MAP["power"])
    # numerici
    for col in [cpu_col, mem_col, power_col]:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    # filtra idle e normalizza CPU per core
    df = df[df[cpu_col] > 0].copy()
    df[cpu_col] = df[cpu_col] / float(cores)
    return df, cpu_col, mem_col, power_col

def stats_for(series):
    s = pd.to_numeric(series, errors="coerce").dropna()
    if s.empty:
        return (np.nan, np.nan, np.nan, np.nan)
    return (s.min(), s.max(), s.mean(), s.std(ddof=1))

# -----------------------------
# Build summary (CSV)
# -----------------------------
def build_summary(root, protocols, switches, configs, cores):
    rows = []
    for proto in protocols:
        for sw in switches:
            for conf_name, conf_file in configs:
                fpath = Path(root) / proto / sw / conf_file
                if not fpath.exists():
                    continue
                try:
                    df, cpu_col, mem_col, power_col = load_and_clean_csv(fpath, cores)
                except Exception as e:
                    print(f"[WARN] Failed reading {fpath}: {e}", file=sys.stderr)
                    continue
                cpu_stats = stats_for(df[cpu_col])
                mem_stats = stats_for(df[mem_col])
                pow_stats = stats_for(df[power_col])
                rows.append([
                    proto, sw, conf_name,
                    cpu_stats[0], cpu_stats[1], cpu_stats[2], cpu_stats[3],
                    mem_stats[0], mem_stats[1], mem_stats[2], mem_stats[3],
                    pow_stats[0], pow_stats[1], pow_stats[2], pow_stats[3],
                ])
    summary = pd.DataFrame(rows, columns=SUMMARY_COLS)
    if summary.empty:
        return summary
    # ordina categorie
    summary["Protocol"] = pd.Categorical(summary["Protocol"], categories=protocols, ordered=True)
    summary["Switch"] = pd.Categorical(summary["Switch"], categories=switches, ordered=True)
    summary["Config"] = pd.Categorical(summary["Config"], categories=[c[0] for c in configs], ordered=True)
    return summary.sort_values(["Protocol", "Switch", "Config"]).reset_index(drop=True)

# -----------------------------
# Main
# -----------------------------
def main():
    parser = argparse.ArgumentParser(description="Resources summary: CSV per protocol/switch/config (CPU/Mem/Power).")
    parser.add_argument("--root", type=str, default=".", help="Root directory (default: current directory).")
    parser.add_argument("--output", type=str, default="resources_report", help="Output directory (default: resources_report).")
    parser.add_argument("--cores", type=int, default=4, help="CPU cores for normalization (default: 4).")
    args = parser.parse_args()

    root = Path(args.root)
    outdir = Path(args.output)
    ensure_dir(outdir)

    # protocolli auto-rilevati (mantieni ordine noto, poi eventuali extra)
    found_protos = [p.name for p in root.iterdir() if p.is_dir()]
    # tieni solo cartelle con *_resources.csv
    protocols = []
    for p in found_protos:
        pdir = root / p
        if any(fp.name.endswith("_resources.csv") for fp in pdir.rglob("*.csv")):
            protocols.append(p)
    # ordina come default, poi eventuali extra
    protocols = [p for p in DEFAULT_PROTOCOLS if p in protocols] + [p for p in protocols if p not in DEFAULT_PROTOCOLS]
    if not protocols:
        print("[ERROR] No protocol directories with *_resources.csv found.", file=sys.stderr)
        sys.exit(2)

    switches = DEFAULT_SWITCHES
    configs = DEFAULT_CONFIGS

    print(f"[INFO] Root: {root}")
    print(f"[INFO] Protocols: {protocols}")
    print(f"[INFO] Switches:  {switches}")
    print(f"[INFO] Configs:   {[c[0] for c in configs]}")

    summary = build_summary(root, protocols, switches, configs, args.cores)
    if summary.empty:
        print("[ERROR] No data found. Check directory structure and filenames.", file=sys.stderr)
        sys.exit(2)

    # salva SOLO CSV
    csv_path = outdir / "resources_summary.csv"
    summary.to_csv(csv_path, index=False)
    print(f"[OK] Saved CSV: {csv_path}")
    print("[DONE]")

if __name__ == "__main__":
    main()
