#!/usr/bin/env python3
import argparse
import re
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

DEFAULT_PROTOCOLS = ["modbus", "dnp3", "mqtt", "ethernet-ip"]
DEFAULT_SWITCHES = ["s1", "s2"]
# DEFAULT_CONFIGS = ["plaintext", "128", "192", "256", "tls"]
DEFAULT_CONFIGS = ["128", "192", "256"]

PPT_KEY = "packet_processing_time_array"
PDT_KEY = "packet_dequeuing_timedelta_array"

NUM_RE = re.compile(r'(-?\d+\.?\d*)')

def parse_registers_file(path: Path):
    """
    Returns dict with optional keys 'ppt' and 'pdt' each mapping to a list of floats.
    """
    if not path.exists():
        return {}
    text = path.read_text(encoding='utf-8', errors='ignore')
    out = {}
    for key, out_key in [(PPT_KEY, 'ppt'), (PDT_KEY, 'pdt')]:
        m = re.search(rf'{re.escape(key)}\s*=\s*([^\n\r]+)', text)
        if m:
            vals_str = m.group(1)
            vals_str = vals_str.split('...')[0]
            nums = [float(x) for x in NUM_RE.findall(vals_str)]
            out[out_key] = nums
    return out

def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

def build_summary(root: Path):
    rows = []
    # prendi solo le cartelle con almeno un *_registers.txt dentro
    protocols = []
    for p in root.iterdir():
        if p.is_dir():
            if any(f.suffix == ".txt" and f.name.endswith("_registers.txt") for f in p.rglob("*")):
                protocols.append(p.name)

    ordered = [p for p in DEFAULT_PROTOCOLS if p in protocols]
    extras = [p for p in protocols if p not in DEFAULT_PROTOCOLS]
    protocols = ordered + extras if protocols else DEFAULT_PROTOCOLS

    for proto in protocols:
        for sw in DEFAULT_SWITCHES:
            for conf in DEFAULT_CONFIGS:
                fname = f"{conf}_registers.txt"
                fpath = root / proto / sw / fname
                parsed = parse_registers_file(fpath)
                ppt = parsed.get('ppt', [])
                pdt = parsed.get('pdt', [])
                ppt_mean = float(np.mean(ppt)) if len(ppt) > 0 else np.nan
                pdt_mean = float(np.mean(pdt)) if len(pdt) > 0 else np.nan
                ppt_std = float(np.std(ppt, ddof=1)) if len(ppt) > 1 else np.nan
                pdt_std = float(np.std(pdt, ddof=1)) if len(pdt) > 1 else np.nan
                rows.append({
                    "Protocol": proto,
                    "Switch": sw,
                    "Config": conf,
                    "PPT_Count": len(ppt),
                    "PPT_Mean": ppt_mean,
                    "PPT_Std": ppt_std,
                    "PDT_Count": len(pdt),
                    "PDT_Mean": pdt_mean,
                    "PDT_Std": pdt_std,
                })
    df = pd.DataFrame(rows)
    df["Protocol"] = pd.Categorical(df["Protocol"], categories=protocols, ordered=True)
    df["Switch"] = pd.Categorical(df["Switch"], categories=DEFAULT_SWITCHES, ordered=True)
    df["Config"] = pd.Categorical(df["Config"], categories=DEFAULT_CONFIGS, ordered=True)
    df = df.sort_values(["Protocol", "Switch", "Config"]).reset_index(drop=True)
    return df, protocols

def _format_xticklabels(configs):
    label_map = {
        "128": "128 bit\nkey",
        "192": "192 bit\nkey",
        "256": "256 bit\nkey",
        "plaintext": "plaintext",
        "tls": "tls"
    }
    return [label_map.get(c, str(c)) for c in configs]

def plot_overlay_bars_for_protocol(df_proto, metric_col, outpath, title_suffix):
    """
    One figure per protocol:
      X = configurations
      Y = mean metric
      Two side-by-side bars: s1 (left) and s2 (right), con error bar rosse (± std)
      e testo con il mean sopra ogni barra.
    """
    configs = DEFAULT_CONFIGS

    # mean & std per s1
    df_s1 = df_proto[df_proto["Switch"] == "s1"].set_index("Config")
    means_s1 = df_s1[metric_col].reindex(configs).values
    std_col = metric_col.replace("Mean", "Std")  # "PPT_Mean" -> "PPT_Std"
    stds_s1 = df_s1[std_col].reindex(configs).values

    # mean & std per s2
    df_s2 = df_proto[df_proto["Switch"] == "s2"].set_index("Config")
    means_s2 = df_s2[metric_col].reindex(configs).values
    stds_s2 = df_s2[std_col].reindex(configs).values

    x = np.arange(len(configs))
    width = 0.38

    fig, ax = plt.subplots(figsize=(9, 5.5))

    # barre
    b1 = ax.bar(x - width/2, means_s1, width=width, label="s1", alpha=0.9, zorder=0)
    b2 = ax.bar(x + width/2, means_s2, width=width, label="s2", alpha=0.9, zorder=0, hatch='//')

    # error bar settings (rosse)
    error_kw = dict(elinewidth=2, ecolor="red", capsize=6)

    # yerr può contenere NaN: matplotlib li ignora
    ax.errorbar(x - width/2, means_s1, yerr=stds_s1, fmt='none', **error_kw, zorder=2)
    ax.errorbar(x + width/2, means_s2, yerr=stds_s2, fmt='none', **error_kw, zorder=2)
    # marker dei mean (rossi, come nel tuo esempio)
    ax.errorbar(x - width/2, means_s1, yerr=stds_s1, fmt='o', color='red', mfc='white',
                ecolor='red', elinewidth=2, capsize=6, markersize=6, zorder=3)
    ax.errorbar(x + width/2, means_s2, yerr=stds_s2, fmt='o', color='red', mfc='white',
                ecolor='red', elinewidth=2, capsize=6, markersize=6, zorder=3)

    # testo con mean sopra le barre (fontsize 18)
    # per il posizionamento verticale uso max(means+stds) della coppia come scala
    def annotate_means(xpos, means, stds):
        # protezione: se tutto NaN, salta
        if np.all(np.isnan(means)):
            return
        # calcolo scala per il padding
        combo = []
        for m, s in zip(means, stds):
            if np.isnan(m):
                continue
            pad = 0.0 if np.isnan(s) else s
            combo.append(m + pad)
        base = np.nanmax(combo) if combo else (np.nanmax(means) if not np.all(np.isnan(means)) else 0.0)
        pad_scale = 0.02 * float(base if base > 0 else (np.nanmax(means) if np.nanmax(means) > 0 else 1.0))

        for xm, mean, std in zip(xpos, means, stds):
            if np.isnan(mean):
                continue
            y_text = mean + pad_scale
            ax.text(xm + 0.02, y_text, f"{mean:.3f}", ha="left", va="bottom", fontsize=18)

    annotate_means(x - width/2, means_s1, stds_s1)
    annotate_means(x + width/2, means_s2, stds_s2)

    # xticks formattati e font size
    ax.set_xticks(x)
    ax.set_xticklabels(_format_xticklabels(configs), fontsize=18)

    # yticks fontsize 18
    ax.tick_params(axis='y', labelsize=18)

    # ylabel fontsize 20
    ax.set_ylabel(metric_col.replace('_', ' '), fontsize=20)

    # legenda fontsize 18
    ax.legend(fontsize=18)

    # opzionale: baseline a 0
    ax.set_ylim(bottom=0)

    fig.tight_layout()
    fig.savefig(outpath)
    plt.close(fig)

def main():
    parser = argparse.ArgumentParser(description="Generate bar charts from *_registers.txt files.")
    parser.add_argument("--root", type=str, default=".", help="Root directory with protocol/switch files (default: current dir).")
    parser.add_argument("--output", type=str, default="registers_report", help="Output directory for charts and CSV (default: registers_report).")
    args = parser.parse_args()

    root = Path(args.root)
    outdir = Path(args.output)
    ensure_dir(outdir)

    df, protocols = build_summary(root)

    # Save summary CSV
    csv_path = outdir / "registers_summary.csv"
    df.to_csv(csv_path, index=False)

    # Charts
    for proto in protocols:
        subset = df[df["Protocol"] == proto]
        out1 = outdir / f"ppt_{proto}.pdf"
        plot_overlay_bars_for_protocol(subset, "PPT_Mean", out1, "Packet Processing Time (mean)")
        out2 = outdir / f"pdt_{proto}.pdf"
        plot_overlay_bars_for_protocol(subset, "PDT_Mean", out2, "Packet Dequeuing Timedelta (mean)")

    print(f"Saved summary: {csv_path}")
    print("Done.")

if __name__ == '__main__':
    main()
