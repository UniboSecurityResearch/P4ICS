#!/bin/bash
# Monitor processes matched by a command pattern.
# CPU% from `top -b -n 1` (same numbers as top/htop), Memory from `ps` (RSS -> MB).
# Logs to CSV; on CTRL+C dumps switch registers via simple_switch_CLI.
# Dependencies: top, ps, awk, bc; optional: vcgencmd, simple_switch_CLI
# Usage examples: ./monitor.sh --cmd "simple_switch"

set -o pipefail

# ===== Configuration =====
INTERVAL_SEC=0.5            # sampling interval in seconds
PATTERN=""                  # regex to match full command line, e.g., "simple_switch"

usage() {
  echo "Usage: $0 --cmd \"pattern\" [--interval SECONDS]"
  echo "Examples:"
  echo "  $0 --cmd \"simple_switch\""
  echo "  $0 --cmd \"simple_switch -i 1@eth0 AES.json --log-console\" --interval 1"
}

# ===== Parse args =====
while [[ $# -gt 0 ]]; do
  case "$1" in
    --cmd|--pattern) PATTERN="$2"; shift 2 ;;
    --interval) INTERVAL_SEC="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

if [[ -z "$PATTERN" ]]; then
  echo "Error: you must provide --cmd \"pattern\""
  usage
  exit 1
fi

# ===== Optional tools =====
VCGENCMD_AVAILABLE=true
command -v vcgencmd >/dev/null 2>&1 || VCGENCMD_AVAILABLE=false
SWCLI_AVAILABLE=true
command -v simple_switch_CLI >/dev/null 2>&1 || SWCLI_AVAILABLE=false

# ===== Output files =====
TS="$(date +"%Y%m%d_%H%M%S")"
sanitize() { tr -cs '[:alnum:]' '_' <<<"$1"; }
ID="topmon_cmd_$(sanitize "$PATTERN")_${TS}"
RES_FILE="${ID}_resources.csv"
REG_FILE="${ID}_switch_registers.txt"

echo "Monitoring (CPU from top, MEM from ps) for pattern: $PATTERN"
echo "• Resource CSV : $RES_FILE"
echo "• Switch regs  : $REG_FILE"
[[ "$VCGENCMD_AVAILABLE" = false ]] && echo "Warning: 'vcgencmd' not found. Voltage will be empty."
[[ "$SWCLI_AVAILABLE"   = false ]] && echo "Warning: 'simple_switch_CLI' not found. Switch register dump will be skipped."

# Force C locale (dot decimals) for consistent parsing
export LC_ALL=C
export LANG=C

# ===== CSV header =====
echo "Timestamp, ProcCount, CPU_Total (%), Memory_Total (MB), Voltage (V), PIDs" > "$RES_FILE"

# ===== Arrays for stats =====
cpu_vals=()
mem_vals=()
volt_vals=()

# ===== Helpers =====

# List PIDs by matching pattern on full command line
get_pids_by_pattern() {
  local pat="$1"
  ps ax -o pid=,command= | awk -v pat="$pat" '$0 ~ pat {print $1}'
}

# Sum %CPU using `top -b -n 1` for a set of PIDs.
# GNU top limits -p to ~20 PIDs per invocation; chunk the list safely.
top_cpu_sum_for_pids() {
  local -a pids=("$@")
  local chunk_size=20
  local total=0.0

  if [ ${#pids[@]} -eq 0 ]; then
    printf "0.00"
    return
  fi

  local i=0
  while [ $i -lt ${#pids[@]} ]; do
    local -a args=(-b -n 1)
    local j=0
    while [ $j -lt $chunk_size ] && [ $((i+j)) -lt ${#pids[@]} ]; do
      args+=(-p "${pids[$((i+j))]}")
      j=$((j+1))
    done

    # Run top in batch for this chunk and sum column %CPU ($9) for numeric PID lines
    # Note: some top builds print a header then one line per PID.
    local sum_chunk
    sum_chunk=$(top "${args[@]}" 2>/dev/null | \
      awk '($1+0)>0 {cpu+=$9} END{printf("%.2f", (cpu+0))}')

    # Accumulate as float
    total=$(awk -v a="$total" -v b="$sum_chunk" 'BEGIN{printf("%.4f", a+b)}')

    i=$((i+chunk_size))
  done

  # Return with 2 decimals
  printf "%.2f" "$(awk -v x="$total" 'BEGIN{printf("%.2f", x+0)}')"
}

# Sum RSS (KB) for PIDs via ps; return MB with two decimals
ps_mem_mb_for_pids() {
  local -a pids=("$@")
  if [ ${#pids[@]} -eq 0 ]; then
    echo "0.00"
    return
  fi
  local pid_csv; pid_csv=$(IFS=, ; echo "${pids[*]}")
  local rss_kb_sum
  rss_kb_sum=$(ps -o rss= -p "$pid_csv" 2>/dev/null | awk '{s+=$1} END{printf("%.2f", s)}')
  # KB -> MB
  echo "$(echo "scale=2; $rss_kb_sum/1024" | bc)"
}

dump_switch_registers() {
  if [ "$SWCLI_AVAILABLE" = false ]; then
    echo "simple_switch_CLI not available: skipping switch dump."
    return
  fi
  {
    echo "packet_processing_time_array:"
    echo "register_read packet_processing_time_array" | simple_switch_CLI
    echo ""
    echo "packet_dequeuing_timedelta_array:"
    echo "register_read packet_dequeuing_timedelta_array" | simple_switch_CLI
  } > "$REG_FILE"
  echo "Switch registers saved in: $REG_FILE"
}

calc_mean() { awk 'BEGIN{sum=0} {for(i=1;i<=NF;i++) sum+=$i} END{if(NF) printf("%.2f", sum/NF); else print "0.00"}' <<< "$*"; }
calc_max()  { awk '{max=$1; for(i=2;i<=NF;i++) if($i>max) max=$i; printf("%.2f", max)}' <<< "$*"; }

print_stats_and_exit() {
  echo
  echo "CTRL+C received: computing statistics and dumping registers..."

  cpu_mean=$(calc_mean "${cpu_vals[@]}")
  mem_mean=$(calc_mean "${mem_vals[@]}")
  volt_mean=$(calc_mean "${volt_vals[@]}")

  cpu_max=$(calc_max "${cpu_vals[@]}")
  mem_max=$(calc_max "${mem_vals[@]}")
  volt_max=$(calc_max "${volt_vals[@]}")

  echo "Aggregate statistics over matched processes:"
  echo "• CPU total     -> Mean=${cpu_mean}%  Max=${cpu_max}%"
  echo "• Memory total  -> Mean=${mem_mean} MB  Max=${mem_max} MB"
  if [ ${#volt_vals[@]} -gt 0 ]; then
    echo "• Voltage       -> Mean=${volt_mean} V  Max=${volt_max} V"
  else
    echo "• Voltage       -> not available"
  fi

  dump_switch_registers
  exit 0
}

trap print_stats_and_exit SIGINT

# ===== Monitoring loop =====
while : ; do
  # 1) Resolve current PID set by pattern
  mapfile -t PID_LIST < <(get_pids_by_pattern "$PATTERN")

  # Exclude our own PID if accidentally matched
  SELF="$$"
  TMP=()
  for p in "${PID_LIST[@]}"; do
    [[ "$p" != "$SELF" ]] && TMP+=("$p")
  done
  PID_LIST=("${TMP[@]}")

  # If nothing matches anymore, exit
  if [ ${#PID_LIST[@]} -eq 0 ]; then
    echo "No matching processes remain. Exiting."
    break
  fi

  timestamp=$(date +"%Y-%m-%d %H:%M:%S")

  # 2) CPU from top (batch); chunk to avoid -p limit
  CPU_SUM="$(top_cpu_sum_for_pids "${PID_LIST[@]}")"

  # 3) Memory from ps (RSS KB -> MB)
  MEM_MB="$(ps_mem_mb_for_pids "${PID_LIST[@]}")"

  # 4) Voltage (optional)
  if [ "$VCGENCMD_AVAILABLE" = true ]; then
    VOLTAGE=$(vcgencmd measure_volts 2>/dev/null | cut -d "=" -f2 | sed 's/V//')
  else
    VOLTAGE=""
  fi

  # 5) Append to CSV
  PID_STR=$(printf "%s " "${PID_LIST[@]}"); PID_STR="${PID_STR% }"
  printf "%s, %d, %.2f, %.2f, %s, \"%s\"\n" \
    "$timestamp" "${#PID_LIST[@]}" "$CPU_SUM" "$MEM_MB" "${VOLTAGE}" "$PID_STR" >> "$RES_FILE"

  # 6) Collect for stats
  cpu_vals+=("$CPU_SUM")
  mem_vals+=("$MEM_MB")
  [[ -n "$VOLTAGE" ]] && volt_vals+=("$VOLTAGE")

  # 7) Sleep
  sleep "$INTERVAL_SEC"
done

echo "Data collected in: $RES_FILE"
echo "Switch registers file will be created only if you stop with CTRL+C."
