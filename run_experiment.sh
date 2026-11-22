#!/usr/bin/env bash
###############################################################################
#  run_experiment.sh — Master Experiment Orchestrator
#
#  Bounded TCP SYN Flooding and Resilience Testing
#  Course: CS74136 / CS012702, NIT Patna, Jul-Dec 2026
#
#  This script automates the full experiment workflow:
#    1. Prerequisite checks
#    2. Baseline measurement (no attack)
#    3. SYN flood attack without defenses
#    4. SYN flood attack with defenses
#    5. Analysis and report generation
#
#  Usage:
#    chmod +x run_experiment.sh
#    sudo ./run_experiment.sh [--target-ip IP] [--target-port PORT] [--rate PPS]
#
#  SAFETY: This script must be run ONLY on an isolated host-only virtual
#  network. It will refuse to run if the target IP is not in a private range.
###############################################################################

set -euo pipefail

# ===========================================================================
#  Configuration — adjust these or pass via CLI flags
# ===========================================================================
TARGET_IP="${TARGET_IP:-192.168.47.20}"
TARGET_PORT="${TARGET_PORT:-80}"
ATTACK_RATE="${ATTACK_RATE:-100}"
ATTACK_DURATION="${ATTACK_DURATION:-30}"
BASELINE_DURATION="${BASELINE_DURATION:-10}"
RECOVERY_WAIT="${RECOVERY_WAIT:-10}"
MONITOR_INTERFACE="${MONITOR_INTERFACE:-eth0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# PID tracking for background processes
declare -a BG_PIDS=()

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ===========================================================================
#  Parse CLI arguments
# ===========================================================================
while [[ $# -gt 0 ]]; do
    case "$1" in
        --target-ip)    TARGET_IP="$2";       shift 2 ;;
        --target-port)  TARGET_PORT="$2";     shift 2 ;;
        --rate)         ATTACK_RATE="$2";     shift 2 ;;
        --duration)     ATTACK_DURATION="$2"; shift 2 ;;
        --interface)    MONITOR_INTERFACE="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: sudo $0 [--target-ip IP] [--target-port PORT] [--rate PPS] [--duration SEC] [--interface IFACE]"
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ===========================================================================
#  Utility Functions
# ===========================================================================

banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║     Bounded TCP SYN Flooding and Resilience Testing            ║"
    echo "║     CS74136 — Network and Systems Security — NIT Patna         ║"
    echo "║     Automated Experiment Runner                                ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info()    { echo -e "${GREEN}[INFO]${NC}  $(date '+%H:%M:%S') — $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $(date '+%H:%M:%S') — $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $(date '+%H:%M:%S') — $*"; }
log_step()    { echo -e "\n${BOLD}${CYAN}═══ $* ═══${NC}\n"; }

# Clean up background processes on exit
cleanup() {
    log_info "Cleaning up background processes..."
    for pid in "${BG_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
            log_info "  Stopped PID $pid"
        fi
    done
    log_info "Cleanup complete."
}
trap cleanup EXIT INT TERM

# Validate that an IP is in a private RFC 1918 range
is_private_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^10\. ]] || \
       [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] || \
       [[ "$ip" =~ ^192\.168\. ]]; then
        return 0
    fi
    return 1
}

# Wait with a countdown
countdown() {
    local secs=$1
    local label="${2:-Waiting}"
    for ((i = secs; i > 0; i--)); do
        printf "\r  ${YELLOW}%s... %d seconds remaining${NC}  " "$label" "$i"
        sleep 1
    done
    printf "\r  %-60s\n" "$label... done."
}

# ===========================================================================
#  Step 0: Banner and Safety Checks
# ===========================================================================

banner

echo -e "${RED}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║  WARNING: This tool performs SYN flooding for EDUCATIONAL       ║${NC}"
echo -e "${RED}║  purposes ONLY. Use exclusively on isolated lab networks.       ║${NC}"
echo -e "${RED}║  Unauthorized use is a criminal offense.                        ║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ===========================================================================
#  Step 1: Check Prerequisites
# ===========================================================================

log_step "STEP 1: Checking Prerequisites"

ERRORS=0

# Check root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root (sudo). Raw sockets require elevated privileges."
    exit 1
fi
log_info "Running as root ✓"

# Check private IP
if ! is_private_ip "$TARGET_IP"; then
    log_error "Target IP ($TARGET_IP) is NOT in a private RFC 1918 range. Aborting for safety."
    exit 1
fi
log_info "Target IP ($TARGET_IP) is in private range ✓"

# Check Python 3
if command -v python3 &>/dev/null; then
    PY_VERSION=$(python3 --version 2>&1)
    log_info "Python 3 found: $PY_VERSION ✓"
else
    log_error "Python 3 not found. Install it with: sudo apt install python3"
    ((ERRORS++))
fi

# Check Scapy
if python3 -c "import scapy" 2>/dev/null; then
    log_info "Scapy module available ✓"
else
    log_error "Scapy not found. Install with: pip install scapy"
    ((ERRORS++))
fi

# Check matplotlib
if python3 -c "import matplotlib" 2>/dev/null; then
    log_info "matplotlib module available ✓"
else
    log_error "matplotlib not found. Install with: pip install matplotlib"
    ((ERRORS++))
fi

# Check required script files
for script in syn_flood.py target_server.py monitor.py defense.py analyze_results.py; do
    if [[ -f "${SCRIPT_DIR}/${script}" ]]; then
        log_info "Found ${script} ✓"
    else
        log_error "Missing ${script} in ${SCRIPT_DIR}"
        ((ERRORS++))
    fi
done

# Check network connectivity to target
if ping -c 1 -W 2 "$TARGET_IP" &>/dev/null; then
    log_info "Target $TARGET_IP is reachable ✓"
else
    log_warn "Target $TARGET_IP is not reachable — it may not be running yet."
fi

if [[ $ERRORS -gt 0 ]]; then
    log_error "$ERRORS prerequisite(s) failed. Fix the above errors and retry."
    exit 1
fi

log_info "All prerequisites satisfied."

echo ""
echo -e "  ${BOLD}Experiment Configuration:${NC}"
echo "    Target IP:        $TARGET_IP"
echo "    Target Port:      $TARGET_PORT"
echo "    Attack Rate:      $ATTACK_RATE pps"
echo "    Attack Duration:  $ATTACK_DURATION seconds"
echo "    Baseline Window:  $BASELINE_DURATION seconds"
echo "    Monitor Iface:    $MONITOR_INTERFACE"
echo ""

# ===========================================================================
#  Step 2: Start Target Server
# ===========================================================================

log_step "STEP 2: Starting Target Server"

# Note: In a real multi-VM setup, the target server runs on the Target VM.
# This script assumes all components run on the same machine for convenience.
# Adjust as needed for your lab topology.

log_info "Launching target_server.py on port $TARGET_PORT..."
python3 "${SCRIPT_DIR}/target_server.py" --port "$TARGET_PORT" &
SERVER_PID=$!
BG_PIDS+=("$SERVER_PID")
log_info "Target server started (PID: $SERVER_PID)"
sleep 2

# Verify the server is running
if kill -0 "$SERVER_PID" 2>/dev/null; then
    log_info "Target server is running ✓"
else
    log_error "Target server failed to start. Check target_server.py for errors."
    exit 1
fi

# ===========================================================================
#  Step 3: Start Monitor
# ===========================================================================

log_step "STEP 3: Starting Network Monitor"

TOTAL_MONITOR_DURATION=$(( BASELINE_DURATION + ATTACK_DURATION + RECOVERY_WAIT + ATTACK_DURATION + RECOVERY_WAIT + 30 ))

log_info "Launching monitor.py for ~${TOTAL_MONITOR_DURATION}s..."
python3 "${SCRIPT_DIR}/monitor.py" \
    --interface "$MONITOR_INTERFACE" \
    --target-ip "$TARGET_IP" \
    --target-port "$TARGET_PORT" \
    --duration "$TOTAL_MONITOR_DURATION" &
MONITOR_PID=$!
BG_PIDS+=("$MONITOR_PID")
log_info "Monitor started (PID: $MONITOR_PID)"
sleep 2

# ===========================================================================
#  Step 4: Baseline Measurement (No Attack)
# ===========================================================================

log_step "STEP 4: Baseline Measurement (No Attack)"

log_info "Collecting baseline data for $BASELINE_DURATION seconds..."
log_info "Server is running normally — no attack traffic."
countdown "$BASELINE_DURATION" "Baseline collection"
log_info "Baseline measurement complete."

# ===========================================================================
#  Step 5: SYN Flood Attack (No Defenses)
# ===========================================================================

log_step "STEP 5: SYN Flood Attack — WITHOUT Defenses"

log_info "Launching SYN flood: rate=$ATTACK_RATE pps, duration=$ATTACK_DURATION s"
python3 "${SCRIPT_DIR}/syn_flood.py" \
    --target-ip "$TARGET_IP" \
    --target-port "$TARGET_PORT" \
    --rate "$ATTACK_RATE" \
    --duration "$ATTACK_DURATION" &
ATTACK_PID=$!
BG_PIDS+=("$ATTACK_PID")
log_info "Attack started (PID: $ATTACK_PID)"

# Wait for attack to finish
log_info "Waiting for attack to complete..."
wait "$ATTACK_PID" 2>/dev/null || true
log_info "Attack phase 1 (no defense) complete."

# ===========================================================================
#  Step 6: Recovery Period
# ===========================================================================

log_step "STEP 6: Recovery Period"

log_info "Allowing server to recover for $RECOVERY_WAIT seconds..."
countdown "$RECOVERY_WAIT" "Recovery"
log_info "Recovery period complete."

# ===========================================================================
#  Step 7: Apply Defenses
# ===========================================================================

log_step "STEP 7: Applying Defensive Measures"

log_info "Applying all defenses via defense.py --mode all..."
python3 "${SCRIPT_DIR}/defense.py" --mode all
log_info "All defenses applied ✓"

# ===========================================================================
#  Step 8: SYN Flood Attack (With Defenses)
# ===========================================================================

log_step "STEP 8: SYN Flood Attack — WITH Defenses"

log_info "Launching SYN flood with defenses active: rate=$ATTACK_RATE pps, duration=$ATTACK_DURATION s"
python3 "${SCRIPT_DIR}/syn_flood.py" \
    --target-ip "$TARGET_IP" \
    --target-port "$TARGET_PORT" \
    --rate "$ATTACK_RATE" \
    --duration "$ATTACK_DURATION" &
ATTACK2_PID=$!
BG_PIDS+=("$ATTACK2_PID")
log_info "Attack started (PID: $ATTACK2_PID)"

# Wait for attack to finish
log_info "Waiting for attack to complete..."
wait "$ATTACK2_PID" 2>/dev/null || true
log_info "Attack phase 2 (with defense) complete."

# ===========================================================================
#  Step 9: Stop Everything
# ===========================================================================

log_step "STEP 9: Stopping All Components"

# Stop monitor
if kill -0 "$MONITOR_PID" 2>/dev/null; then
    kill "$MONITOR_PID" 2>/dev/null || true
    wait "$MONITOR_PID" 2>/dev/null || true
    log_info "Monitor stopped."
fi

# Stop server
if kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    log_info "Target server stopped."
fi

# Reset defenses
log_info "Resetting defenses to defaults..."
python3 "${SCRIPT_DIR}/defense.py" --mode reset
log_info "Defenses reset ✓"

# ===========================================================================
#  Step 10: Run Analysis
# ===========================================================================

log_step "STEP 10: Analyzing Results"

log_info "Running analyze_results.py..."
python3 "${SCRIPT_DIR}/analyze_results.py"
log_info "Analysis complete."

# ===========================================================================
#  Step 11: Summary
# ===========================================================================

log_step "EXPERIMENT COMPLETE"

echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                   Experiment Summary                            ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC}  Target:           $TARGET_IP:$TARGET_PORT"
echo -e "${GREEN}║${NC}  Attack Rate:      $ATTACK_RATE packets/sec"
echo -e "${GREEN}║${NC}  Attack Duration:  $ATTACK_DURATION seconds (×2 phases)"
echo -e "${GREEN}║${NC}  Baseline Window:  $BASELINE_DURATION seconds"
echo -e "${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  ${BOLD}Generated Log Files:${NC}"
for f in syn_flood_log.csv server_log.csv monitor_log.csv defense_log.csv; do
    if [[ -f "${SCRIPT_DIR}/${f}" ]]; then
        SIZE=$(du -h "${SCRIPT_DIR}/${f}" | cut -f1)
        echo -e "${GREEN}║${NC}    ✓ ${f}  ($SIZE)"
    else
        echo -e "${GREEN}║${NC}    ✗ ${f}  (not found)"
    fi
done
echo -e "${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  ${BOLD}Generated Charts:${NC}"
for f in chart_syn_rate_timeline.png chart_server_connections.png \
         chart_connection_states.png chart_defense_comparison.png \
         chart_response_time.png; do
    if [[ -f "${SCRIPT_DIR}/${f}" ]]; then
        echo -e "${GREEN}║${NC}    ✓ ${f}"
    else
        echo -e "${GREEN}║${NC}    ✗ ${f}  (not generated)"
    fi
done
echo -e "${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  ${BOLD}Analysis Report:${NC}"
if [[ -f "${SCRIPT_DIR}/analysis_report.txt" ]]; then
    echo -e "${GREEN}║${NC}    ✓ analysis_report.txt"
else
    echo -e "${GREEN}║${NC}    ✗ analysis_report.txt  (not generated)"
fi
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"

echo ""
log_info "All experiment phases completed successfully."
log_info "Review the generated charts and analysis_report.txt for findings."
echo ""
