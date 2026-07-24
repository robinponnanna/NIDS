#!/usr/bin/env bash
# =============================================================================
# NIDS Rule Simulator
# Triggers the 3 enabled detection rules in rules.json:
#   Rule 3 — TCP Port Scan   (>= 4 new TCP connections / 3 seconds per src_ip)
#   Rule 4 — UDP Port Scan   (>= 15 UDP packets     / 1 second  per src_ip)
#   Rule 5 — ARP Scan        (>= 5  ARP packets     / 3 seconds per src_ip)
#
# Usage:
#   sudo ./simulation.sh [OPTIONS]
#
# Options:
#   -t <ip>        Target IP to send packets to  (default: 172.17.25.12)
#   -i <iface>     Interface to use              (default: wlan0)
#   -r <3|4|5|all> Which rule to simulate        (default: all)
#   -h             Show this help
# =============================================================================

set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────────
TARGET_IP="172.17.25.12"
IFACE="wlan0"
RUN_RULE="all"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Argument parsing ──────────────────────────────────────────────────────────
while getopts "t:i:r:h" opt; do
    case $opt in
        t) TARGET_IP="$OPTARG" ;;
        i) IFACE="$OPTARG" ;;
        r) RUN_RULE="$OPTARG" ;;
        h)
            sed -n '/^# Usage:/,/^# ====/p' "$0" | head -n -1
            exit 0
            ;;
        *) echo "Unknown option. Use -h for help."; exit 1 ;;
    esac
done

# ── Privilege check ───────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] This script requires root privileges (raw sockets).${NC}"
    echo -e "    Run: ${BOLD}sudo $0 $*${NC}"
    exit 1
fi

# ── Tool check ────────────────────────────────────────────────────────────────
for tool in hping3 arp-scan; do
    if ! command -v "$tool" &>/dev/null; then
        echo -e "${RED}[!] Required tool not found: $tool${NC}"
        exit 1
    fi
done

print_banner() {
    echo -e "${BOLD}${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                   NIDS Rule Simulator                        ║"
    printf "║  Target: %-16s  Interface: %-16s  ║\n" "$TARGET_IP" "$IFACE"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_rule_header() {
    local rule_id="$1"
    local rule_name="$2"
    local threshold="$3"
    echo -e "\n${BOLD}${YELLOW}▶ Rule ${rule_id} — ${rule_name}${NC}"
    echo -e "  ${CYAN}Trigger condition:${NC} ${threshold}"
    echo -e "  ${CYAN}Target:${NC} ${TARGET_IP}   ${CYAN}Interface:${NC} ${IFACE}"
    echo ""
}

print_done() {
    echo -e "  ${GREEN}✓ Packets sent — check nids.log for the alert${NC}"
}

# =============================================================================
# Rule 3 — TCP Port Scan
#   Engine:     counts TCP SYN (no ACK) packets per src_ip within a 3-second
#               sliding window.
#   Threshold:  >= 4 connections in 3 seconds → alert
#   Strategy:   Send 6 SYN-only packets to distinct ports via hping3 --syn.
#               hping3 emits bare SYN packets (no ACK), matching exactly what
#               is_new_tcp_conn checks for.
# =============================================================================
simulate_rule3() {
    print_rule_header 3 "TCP Port Scan" ">= 4 new TCP SYN packets in 3 seconds from same src_ip"

    local PORTS=(22 80 443 8080 3306 5432)
    local BURST=${#PORTS[@]}   # 6 — comfortably above threshold of 4

    echo -e "  Sending ${BURST} TCP SYN packets to ${BURST} different ports..."
    echo -e "  Ports: ${PORTS[*]}"
    echo ""

    for port in "${PORTS[@]}"; do
        printf "    → SYN → %s:%-5s\n" "$TARGET_IP" "$port"
        hping3 --syn \
               --destport "$port" \
               --count 1 \
               --interface "$IFACE" \
               --fast \
               "$TARGET_IP" \
               2>/dev/null || true
    done

    print_done
}

# =============================================================================
# Rule 4 — UDP Port Scan
#   Engine:     every matching UDP ingress packet from a src_ip is counted as a
#               new connection (no SYN concept for UDP).
#   Threshold:  >= 15 UDP packets in 1 second → alert
#   Strategy:   Burst 20 UDP packets via hping3 --udp --fast, keeping all
#               packets inside the 1-second sliding window.
# =============================================================================
simulate_rule4() {
    print_rule_header 4 "UDP Port Scan" ">= 15 UDP packets in 1 second from same src_ip"

    local COUNT=20   # comfortably above threshold of 15

    echo -e "  Sending ${COUNT} UDP packets in rapid burst..."
    echo ""

    # --baseport 53 --keep increments dst port each packet → simulates a scan
    printf "    → UDP burst (%d pkts) → %s:53+\n" "$COUNT" "$TARGET_IP"
    hping3 --udp \
           --baseport 53 \
           --keep \
           --count "$COUNT" \
           --interface "$IFACE" \
           --fast \
           "$TARGET_IP" \
           2>/dev/null || true

    print_done
}

# =============================================================================
# Rule 5 — ARP Scan
#   Engine:     every ARP packet from a src_ip is counted as a new connection.
#   Threshold:  >= 5 ARP packets in 3 seconds → alert
#   Strategy:   arp-scan over a /29 subnet (8 hosts) → 8 ARP who-has requests,
#               above the threshold of 5.  --retry=0 keeps it to one pass.
# =============================================================================
simulate_rule5() {
    print_rule_header 5 "ARP Scan" ">= 5 ARP packets in 3 seconds from same src_ip"

    # Build a /29 subnet around the target (8 addresses)
    local base
    base=$(echo "$TARGET_IP" | awk -F. '{print $1"."$2"."$3".0"}')
    local SUBNET="${base}/29"

    echo -e "  Sending ARP who-has? to 8 hosts in ${SUBNET}..."
    echo ""

    printf "    → ARP who-has? → %s\n" "$SUBNET"
    arp-scan \
        --interface="$IFACE" \
        --retry=0 \
        --timeout=100 \
        "$SUBNET" \
        2>/dev/null || true

    print_done
}

# =============================================================================
# Main
# =============================================================================
print_banner

echo -e "${CYAN}Tip:${NC} In another terminal, run:  ${BOLD}tail -f nids.log${NC}"
echo -e "${CYAN}Running rule(s):${NC} ${RUN_RULE}"
echo ""

case "$RUN_RULE" in
    3)
        simulate_rule3
        ;;
    4)
        simulate_rule4
        ;;
    5)
        simulate_rule5
        ;;
    all)
        simulate_rule3
        sleep 1
        simulate_rule4
        sleep 1
        simulate_rule5
        ;;
    *)
        echo -e "${RED}[!] Unknown rule '${RUN_RULE}'. Use 3, 4, 5, or all.${NC}"
        exit 1
        ;;
esac

echo -e "\n${BOLD}${GREEN}Simulation complete.${NC}"
echo -e "Check ${BOLD}nids.log${NC} for generated alerts."
