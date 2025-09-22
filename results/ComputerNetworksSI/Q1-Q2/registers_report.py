#!/usr/bin/env python3
import argparse
import re
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

# -------------------- Config --------------------
DEFAULT_PROTOCOLS = ["modbus", "dnp3", "mqtt", "ethernet-ip"]
DEFAULT_SWITCHES = ["s1", "s2"]
# Se vuoi anche plaintext/tls rimetti "plaintext","tls"
DEFAULT_CONFIGS = ["128", "192", "256"]

PPT_KEY = "packet_processing_time_array"
PDT_KEY = "packet_dequeuing_timedelta_array"
NUM_RE = re.compile(r'(-?\d+\.?\d*)')

# -------------------- Parsing --------------------
def parse_registers_file(path: Path):
    """
    Ritorna dict {'ppt': [...], 'pdt': [...]} in millisecondi.
    Converte da microsecondi (nei file) a millisecondi.
    """
    if not path.exists():
        return {}
    text = path.read_text(encoding='utf-8', errors='ignore')
    out = {}
    for key, out_key in [(PPT_KEY, 'ppt'), (PDT_KEY, 'pdt')]:
        m = re.search(rf'{re.escape(key)}\s*=\s*([^\n\r]+)', text)
        if not m:
            continue
        vals_str = m.group(1).split('...')[0]
        nums_us = [float(x) for x in NUM_RE.findall(vals_str)]
        nums_ms = [v / 1000.0 for v in nums_us]  # µs -> ms
        out[out_key] = nums_ms
    return out

def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

# -------------------- Summary table --------------------
def build_summary(root: Path):
    rows = []
    # prendi solo cartelle che contengono *_registers.txt
    protocols = []
    for p in root.iterdir():
        if p.is_dir() and any(f.name.endswith("_registers.txt") for f in p.rglob("*.txt")):
            protocols.append(p.name)

    ordered = [p for p in DEFAULT_PROTOCOLS if p in protocols]
    extras = [p for p in protocols if p not in DEFAULT_PROTOCOLS]
    protocols = ordered + extras if protocols else DEFAULT_PROTOCOLS

    for proto in protocols:
        for sw in DEFAULT_SWITCHES:
            for conf in DEFAULT_CONFIGS:
                fpath = root / proto / sw / f"{conf}_registers.txt"
                parsed = parse_registers_file(fpath)
                ppt = parsed.get('ppt', [])
                pdt = parsed.get('pdt', [])
                ppt_mean = float(np.mean(ppt)) if len(ppt) > 0 else np.nan
                pdt_mean = float(np.mean(pdt)) if len(pdt) > 0 else np.nan
                ppt_std  = float(np.std(ppt, ddof=1)) if len(ppt) > 1 else np.nan
                pdt_std  = float(np.std(pdt, ddof=1)) if len(pdt) > 1 else np.nan
                rows.append({
                    "Protocol": proto,
                    "Switch": sw,
                    "Config": conf,
                    "PPT_Count": len(ppt),
                    "PPT_Mean": ppt_mean,  # ms
                    "PPT_Std": ppt_std,    # ms
                    "PDT_Count": len(pdt),
                    "PDT_Mean": pdt_mean,  # ms
                    "PDT_Std": pdt_std,    # ms
                })
    df = pd.DataFrame(rows)
    if df.empty:
        return df, protocols
    df["Protocol"] = pd.Categorical(df["Protocol"], categories=protocols, ordered=True)
    df["Switch"]   = pd.Categorical(df["Switch"],   categories=DEFAULT_SWITCHES, ordered=True)
    df["Config"]   = pd.Categorical(df["Config"],   categories=DEFAULT_CONFIGS,   ordered=True)
    df = df.sort_values(["Protocol", "Switch", "Config"]).reset_index(drop=True)
    return df, protocols

# -------------------- Plot helpers --------------------
def _format_xticklabels(configs):
    label_map = {"128": "128 bit\nkey", "192": "192 bit\nkey", "256": "256 bit\nkey",
                 "plaintext": "plaintext", "tls": "tls"}
    return [label_map.get(c, str(c)) for c in configs]

def _safe_series(df, col, index_order):
    """Restituisce np.array allineato a index_order; se col manca o df vuoto -> NaN."""
    if df.empty or col not in df.columns:
        return np.full(len(index_order), np.nan, dtype=float)
    return df[col].reindex(index_order).values.astype(float)

def plot_overlay_bars_for_protocol(df_proto, metric_col, outpath):
    """
    Un grafico per protocollo:
      X = configurazioni, Y = mean (ms)
      Barre affiancate s1 (sx) e s2 (dx), error bar rosse (±std), mean sopra le barre.
    """
    configs = DEFAULT_CONFIGS
    df_s1 = df_proto[df_proto["Switch"] == "s1"].set_index("Config")
    df_s2 = df_proto[df_proto["Switch"] == "s2"].set_index("Config")

    means_s1 = _safe_series(df_s1, metric_col, configs)
    means_s2 = _safe_series(df_s2, metric_col, configs)
    std_col  = metric_col.replace("Mean", "Std")
    stds_s1  = _safe_series(df_s1, std_col, configs)
    stds_s2  = _safe_series(df_s2, std_col, configs)

    # se tutte NaN, non generare grafico
    if not (np.isfinite(means_s1).any() or np.isfinite(means_s2).any()):
        return

    x = np.arange(len(configs))
    width = 0.38

    fig, ax = plt.subplots(figsize=(9, 5.5))

    # barre con yerr rosse
    error_kw = dict(elinewidth=2, ecolor="red", capsize=6)
    ax.bar(x - width/2, means_s1, width=width, label="s1", alpha=0.9, zorder=0,
           yerr=stds_s1, error_kw=error_kw)
    ax.bar(x + width/2, means_s2, width=width, label="s2", alpha=0.9, zorder=0, hatch='//',
           yerr=stds_s2, error_kw=error_kw)

    # marker rossi sui mean (estetica stile tuo snippet)
    ax.errorbar(x - width/2, means_s1, yerr=stds_s1, fmt='o', color='red', mfc='white',
                ecolor='red', elinewidth=2, capsize=6, markersize=6, zorder=3)
    ax.errorbar(x + width/2, means_s2, yerr=stds_s2, fmt='o', color='red', mfc='white',
                ecolor='red', elinewidth=2, capsize=6, markersize=6, zorder=3)

    # testo del mean sopra le barre (padding 2% del max di (mean+std))
    combo = np.concatenate([
        np.nan_to_num(means_s1) + np.nan_to_num(stds_s1),
        np.nan_to_num(means_s2) + np.nan_to_num(stds_s2)
    ])
    base = np.nanmax(combo) if combo.size and np.isfinite(np.nanmax(combo)) else 1.0
    pad = 0.02 * float(base)

    for xm, mean in zip(x - width/2, means_s1):
        if np.isfinite(mean):
            ax.text(xm, mean + pad, f"{mean:.3f}", ha="center", va="bottom", fontsize=18)
    for xm, mean in zip(x + width/2, means_s2):
        if np.isfinite(mean):
            ax.text(xm, mean + pad, f"{mean:.3f}", ha="center", va="bottom", fontsize=18)

    # ticks/labels
    ax.set_xticks(x)
    ax.set_xticklabels(_format_xticklabels(configs), fontsize=18)
    ax.tick_params(axis='y', labelsize=18)
    ax.set_ylabel("Mean Time (ms)", fontsize=20)
    ax.legend(fontsize=18)
    ax.set_ylim(bottom=0)

    fig.tight_layout()
    fig.savefig(outpath, dpi=200, bbox_inches='tight')
    plt.close(fig)

# -------------------- Main --------------------
def main():
    parser = argparse.ArgumentParser(description="Registers report: CSV + bar charts with std error (ms).")
    parser.add_argument("--root", type=str, default=".", help="Root directory (default: current dir).")
    parser.add_argument("--output", type=str, default="registers_report", help="Output directory (default: registers_report).")
    args = parser.parse_args()

    root = Path(args.root)
    outdir = Path(args.output)
    ensure_dir(outdir)

    df, protocols = build_summary(root)

    # salva CSV
    csv_path = outdir / "registers_summary.csv"
    df.to_csv(csv_path, index=False)
    print(f"Saved summary: {csv_path}")

    # grafici per protocollo (PPT e PDT)
    for proto in protocols:
        subset = df[df["Protocol"] == proto]
        if subset.empty:
            continue
        plot_overlay_bars_for_protocol(subset, "PPT_Mean", outdir / f"ppt_{proto}.pdf")
        plot_overlay_bars_for_protocol(subset, "PDT_Mean", outdir / f"pdt_{proto}.pdf")

    print("Done.")

if __name__ == '__main__':
    main()
