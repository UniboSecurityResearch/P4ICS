#!/usr/bin/env python3
import argparse
import re
from pathlib import Path
import numpy as np
import pandas as pd

# --- Keys & helpers ---
PPT_KEY = "packet_processing_time_array"
PDQ_KEY = "packet_dequeuing_timedelta_array"
NUM_RE = re.compile(r'(-?\d+\.?\d*)')

RESOURCE_COLS = {
    "cpu": "CPU_Total (%)",
    "mem": "Memory_Total (MB)",
    "power": "Voltage (V)",
}

def parse_registers(path: Path):
    """Return dict {'PPT': [...], 'PDQ': [...]} in milliseconds."""
    txt = path.read_text(encoding="utf-8", errors="ignore")
    def grab(key):
        m = re.search(rf'{re.escape(key)}\s*=\s*([^\n\r]+)', txt)
        if not m:
            return []
        vals_str = m.group(1).split("...")[0]
        # convert to ms
        return [float(x)/1000.0 for x in NUM_RE.findall(vals_str)]
    return {"PPT": grab(PPT_KEY), "PDQ": grab(PDQ_KEY)}

def stats(arrlike):
    s = pd.Series(arrlike, dtype="float64").dropna()
    if s.empty:
        return (np.nan, np.nan, np.nan, np.nan)
    return (float(s.min()), float(s.max()), float(s.mean()), float(s.std(ddof=1)))

def find_column(df, expected):
    tgt = expected.lower().replace(" ", "").replace("_", "")
    for c in df.columns:
        cand = str(c).lower().replace(" ", "").replace("_", "")
        if tgt in cand:
            return c
    raise KeyError(f"Colonna attesa non trovata: {expected} (presenti: {list(df.columns)})")

def load_resources(path: Path, cores: int):
    df = pd.read_csv(path, skipinitialspace=True)
    cpu_col = find_column(df, RESOURCE_COLS["cpu"])
    mem_col = find_column(df, RESOURCE_COLS["mem"])
    pow_col = find_column(df, RESOURCE_COLS["power"])
    for col in [cpu_col, mem_col, pow_col]:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df = df[df[cpu_col] > 0].copy()
    df[cpu_col] = df[cpu_col] / float(cores)
    return df, cpu_col, mem_col, pow_col

def compute_row(label, regs_path, res_path, cores):
    regs = parse_registers(regs_path)
    ppt_min, ppt_max, ppt_mean, ppt_std = stats(regs["PPT"])
    pdq_min, pdq_max, pdq_mean, pdq_std = stats(regs["PDQ"])
    df, cpu_col, mem_col, pow_col = load_resources(res_path, cores)
    cpu_min, cpu_max, cpu_mean, cpu_std = stats(df[cpu_col])
    mem_min, mem_max, mem_mean, mem_std = stats(df[mem_col])
    pow_min, pow_max, pow_mean, pow_std = stats(df[pow_col])
    total_mean = (ppt_mean if pd.notna(ppt_mean) else 0.0) + (pdq_mean if pd.notna(pdq_mean) else 0.0)
    return {
        "Impl": label,
        "PPT_Min_ms": ppt_min, "PPT_Max_ms": ppt_max, "PPT_Mean_ms": ppt_mean, "PPT_Std_ms": ppt_std,
        "PDQ_Min_ms": pdq_min, "PDQ_Max_ms": pdq_max, "PDQ_Mean_ms": pdq_mean, "PDQ_Std_ms": pdq_std,
        "Total_Mean_ms": total_mean,
        "CPU_Min": cpu_min, "CPU_Max": cpu_max, "CPU_Mean": cpu_mean, "CPU_Std": cpu_std,
        "Mem_Min": mem_min, "Mem_Max": mem_max, "Mem_Mean": mem_mean, "Mem_Std": mem_std,
        "Power_Min": pow_min, "Power_Max": pow_max, "Power_Mean": pow_mean, "Power_Std": pow_std,
    }

def pct_delta(new, base):
    if pd.isna(base) or base == 0 or pd.isna(new):
        return np.nan
    return 100.0 * (new - base) / base

def main():
    parser = argparse.ArgumentParser(description="Summary CSV: AES_extern vs AES_LUT (PPT/PDQ ms + resources + Total).")
    parser.add_argument("--cores", type=int, default=4, help="Numero di core CPU (default: 4)")
    parser.add_argument("--output", default="summary.csv", help="File CSV di output (default: summary.csv)")
    args = parser.parse_args()

    extern_dir = Path("AES_extern")
    lut_dir    = Path("AES_LUT")

    row_ext = compute_row("AES_extern", extern_dir/"switch_registers.txt", extern_dir/"resources.csv", args.cores)
    row_lut = compute_row("AES_LUT",    lut_dir/"switch_registers.txt",    lut_dir/"resources.csv",    args.cores)

    cols = list(row_ext.keys())
    base = pd.DataFrame([row_ext, row_lut], columns=cols)

    # Riga con differenze percentuali (LUT vs extern) solo per le medie
    delta = {c: np.nan for c in cols}
    delta["Impl"] = "Delta_% (LUT vs extern)"
    for key in ["PPT_Mean_ms","PDQ_Mean_ms","Total_Mean_ms","CPU_Mean","Mem_Mean","Power_Mean"]:
        delta[key] = pct_delta(base.loc[base["Impl"]=="AES_LUT",key].values[0],
                               base.loc[base["Impl"]=="AES_extern",key].values[0])

    out = pd.concat([base, pd.DataFrame([delta])], ignore_index=True)
    out.to_csv(args.output, index=False)
    print(f"Salvato: {args.output}")

if __name__ == "__main__":
    main()
