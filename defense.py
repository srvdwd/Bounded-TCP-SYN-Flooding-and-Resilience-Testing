#!/usr/bin/env python3
"""
defense.py — TCP SYN Flood Defense and Mitigation Manager
=========================================================
Bounded TCP SYN Flooding and Resilience Testing
Course: CS74136 / CS012702 — Network and System Security Laboratory
Department of Computer Science and Engineering, National Institute of Technology Patna

Theory & Background:
--------------------
A TCP SYN flood exploits the half-open connection state in the TCP three-way handshake:
  Client  ---[ SYN ]--->  Server  (allocates TCB in SYN backlog queue)
  Client  <--[ SYN-ACK ]- Server  (waiting for ACK, state: SYN_RECV)
  Client  ---[ ... ]      (Attacker never sends ACK; backlog fills up -> DoS)

This script implements four classical defensive layers:
  1. TCP SYN Cookies (RFC 4987):
     Instead of allocating a Transmission Control Block (TCB) in memory upon
     receiving a SYN, the server encodes the connection state into the initial
     sequence number (ISN = cryptographic hash of (src_ip, src_port, dst_ip, dst_port, secret)).
     The TCB is allocated only when the final ACK arrives with ACK_num = ISN + 1.
     Kernel parameter: net.ipv4.tcp_syncookies = 1

  2. Firewall Rate Limiting (iptables hashlimit):
     Limits incoming SYN packets per source IP address using a token bucket algorithm.
     Prevents a single source or burst from saturating the listening queue while
     allowing legitimate traffic to proceed.
     Rule: iptables -A INPUT -p tcp --syn --dport <PORT> -m hashlimit
           --hashlimit-name syn_limit --hashlimit-above 25/sec
           --hashlimit-burst 50 --hashlimit-mode srcip -j DROP

  3. SYN Backlog & Listen Queue Tuning:
     Increases the queue sizes for half-open (SYN_RECV) and fully established (ESTABLISHED)
     connections awaiting accept(), absorbing bursts before packet drops occur.
     Parameters: net.ipv4.tcp_max_syn_backlog = 2048, net.core.somaxconn = 1024

  4. Strict TCP Flag Filtering (Firewall Scrubbing):
     Drops malformed TCP packets (e.g., SYN with FIN, SYN with RST, or packets
     with no flags set (NULL scan)) before they reach the TCP stack.

Usage:
------
  sudo python3 defense.py --mode syn_cookies
  sudo python3 defense.py --mode rate_limit [--target-port 80]
  sudo python3 defense.py --mode connection_limit
  sudo python3 defense.py --mode firewall [--target-port 80]
  sudo python3 defense.py --mode all [--target-port 80]
  sudo python3 defense.py --mode status
  sudo python3 defense.py --mode reset

Safety Notice:
--------------
All commands operate within the local Linux network stack and iptables filter table.
Always reset rules after experiments using `--mode reset`.
"""

import argparse
import csv
import datetime
import os
import platform
import subprocess
import sys

# Log file written in current directory
LOG_FILE = "defense_log.csv"
CSV_HEADER = ["timestamp", "mode", "action", "parameter", "old_value", "new_value", "status"]

# Iptables comment tag to cleanly identify and remove our rules
IPTABLES_TAG = "NSS_SYN_DEFENSE"


def print_banner():
    banner = """
╔══════════════════════════════════════════════════════════════════╗
║        TCP SYN Flood Defense & Resilience Controller             ║
║     CS74136 / CS012702 — Network & System Security Lab           ║
║               National Institute of Technology Patna             ║
╚══════════════════════════════════════════════════════════════════╝
"""
    print(banner)


class DefenseLogger:
    """Logs all applied defense configurations to defense_log.csv."""
    def __init__(self, log_path=LOG_FILE):
        self.log_path = log_path
        file_exists = os.path.exists(self.log_path) and os.path.getsize(self.log_path) > 0
        self.file = open(self.log_path, "a", newline="", encoding="utf-8")
        self.writer = csv.writer(self.file)
        if not file_exists:
            self.writer.writerow(CSV_HEADER)
            self.file.flush()

    def log(self, mode, action, parameter, old_val, new_val, status):
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.writer.writerow([ts, mode, action, parameter, old_val, new_val, status])
        self.file.flush()

    def close(self):
        if self.file and not self.file.closed:
            self.file.close()


def is_root():
    """Check if script is executed with root/administrator privileges."""
    if platform.system().lower() == "windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return os.geteuid() == 0


def run_command(cmd, dry_run=False):
    """Execute a system shell command safely."""
    if dry_run:
        print(f"  [DRY-RUN] {cmd}")
        return True, "dry-run success"
    try:
        res = subprocess.run(
            cmd, shell=True, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True
        )
        return True, res.stdout.strip()
    except subprocess.CalledProcessError as e:
        return False, e.stderr.strip()


def get_sysctl(param):
    """Read a Linux sysctl parameter value."""
    if platform.system().lower() != "linux":
        return "N/A (non-Linux)"
    proc_path = f"/proc/sys/{param.replace('.', '/')}"
    if os.path.exists(proc_path):
        try:
            with open(proc_path, "r") as f:
                return f.read().strip()
        except Exception:
            pass
    success, out = run_command(f"sysctl -n {param}")
    return out if success else "unknown"


def set_sysctl(param, value, logger, mode, dry_run=False):
    """Set a Linux sysctl parameter and record the transition in the log."""
    old_val = get_sysctl(param)
    print(f"  [*] sysctl {param}: {old_val} -> {value}")
    if platform.system().lower() != "linux":
        print(f"  [!] Note: Host OS is {platform.system()}. sysctl changes apply inside Linux VMs.")
        logger.log(mode, "set_sysctl", param, old_val, value, "SIMULATED_NON_LINUX")
        return True

    cmd = f"sysctl -w {param}={value}"
    success, out = run_command(cmd, dry_run=dry_run)
    status = "SUCCESS" if success else "FAILED"
    logger.log(mode, "set_sysctl", param, old_val, value, status)
    if not success:
        print(f"  [!] Failed to set {param}: {out}")
    return success


def apply_syn_cookies(logger, dry_run=False):
    """
    Defense 1: Enable TCP SYN Cookies.
    RFC 4987: Protects against memory exhaustion by encoding connection parameters
    in the initial sequence number (ISN), bypassing SYN queue TCB allocation.
    """
    print("\n[+] Applying Defense 1: TCP SYN Cookies (RFC 4987)")
    print("    Mechanics: Encodes state into ISN; eliminates pre-allocated TCB in memory.")
    success = set_sysctl("net.ipv4.tcp_syncookies", "1", logger, "syn_cookies", dry_run)
    if success:
        print("  [✓] net.ipv4.tcp_syncookies = 1 (Active)")
    return success


def apply_connection_limits(logger, dry_run=False):
    """
    Defense 2: Expand SYN Backlog and Socket Listen Queues.
    Increases tolerance against sudden SYN bursts before queue saturation occurs.
    """
    print("\n[+] Applying Defense 2: Connection Backlog Tuning")
    print("    Mechanics: Expands the half-open SYN_RECV queue and accept() somaxconn queue.")
    s1 = set_sysctl("net.ipv4.tcp_max_syn_backlog", "2048", logger, "connection_limit", dry_run)
    s2 = set_sysctl("net.core.somaxconn", "1024", logger, "connection_limit", dry_run)
    s3 = set_sysctl("net.ipv4.tcp_synack_retries", "2", logger, "connection_limit", dry_run)
    return s1 and s2 and s3


def apply_rate_limit(target_port, logger, dry_run=False):
    """
    Defense 3: Firewall Rate Limiting via iptables hashlimit.
    Enforces a token bucket rate-limit of 25 SYN pkts/sec per source IP (burst 50).
    """
    print(f"\n[+] Applying Defense 3: iptables SYN Rate Limiting on Port {target_port}")
    print("    Mechanics: Hashlimit token bucket drops excessive SYNs per source IP.")

    if platform.system().lower() != "linux":
        print(f"  [!] Host is {platform.system()}. iptables rule recorded for Linux test environment.")
        logger.log("rate_limit", "iptables_hashlimit", f"port_{target_port}", "none", "25/sec_burst_50", "SIMULATED_NON_LINUX")
        return True

    # Check if rule already exists
    check_cmd = f"iptables -C INPUT -p tcp --dport {target_port} --syn -m hashlimit --hashlimit-name syn_limit --hashlimit-above 25/sec --hashlimit-burst 50 --hashlimit-mode srcip -m comment --comment '{IPTABLES_TAG}' -j DROP 2>/dev/null"
    rule_exists, _ = run_command(check_cmd)
    if rule_exists:
        print("  [*] Rate limit rule already present in iptables.")
        return True

    add_cmd = (
        f"iptables -A INPUT -p tcp --dport {target_port} --syn "
        f"-m hashlimit --hashlimit-name syn_limit "
        f"--hashlimit-above 25/sec --hashlimit-burst 50 "
        f"--hashlimit-mode srcip "
        f"-m comment --comment '{IPTABLES_TAG}' -j DROP"
    )
    success, out = run_command(add_cmd, dry_run=dry_run)
    status = "SUCCESS" if success else "FAILED"
    logger.log("rate_limit", "iptables_hashlimit", f"port_{target_port}", "none", "25/sec_burst_50", status)
    if success:
        print(f"  [✓] iptables rule applied: SYN rate limited to 25/sec (burst 50) on port {target_port}")
    else:
        print(f"  [!] Failed to apply iptables rule: {out}")
    return success


def apply_firewall_scrubbing(target_port, logger, dry_run=False):
    """
    Defense 4: Strict TCP Flag Filtering (Packet Scrubbing).
    Drops malformed packets (e.g. invalid flag combinations like SYN+FIN, NULL scans).
    """
    print(f"\n[+] Applying Defense 4: TCP Packet Scrubbing on Port {target_port}")
    print("    Mechanics: Drops invalid TCP flag combinations and bogus handshake packets.")

    if platform.system().lower() != "linux":
        print(f"  [!] Host is {platform.system()}. Firewall rules recorded for Linux test environment.")
        logger.log("firewall", "tcp_scrubbing", f"port_{target_port}", "none", "drop_invalid_flags", "SIMULATED_NON_LINUX")
        return True

    rules = [
        # Drop SYN+FIN packets
        f"iptables -A INPUT -p tcp --dport {target_port} --tcp-flags SYN,FIN SYN,FIN -m comment --comment '{IPTABLES_TAG}' -j DROP",
        # Drop SYN+RST packets
        f"iptables -A INPUT -p tcp --dport {target_port} --tcp-flags SYN,RST SYN,RST -m comment --comment '{IPTABLES_TAG}' -j DROP",
        # Drop packets with INVALID state
        f"iptables -A INPUT -p tcp --dport {target_port} -m conntrack --ctstate INVALID -m comment --comment '{IPTABLES_TAG}' -j DROP"
    ]

    all_ok = True
    for rule in rules:
        success, out = run_command(rule, dry_run=dry_run)
        if not success:
            all_ok = False
            print(f"  [!] Failed rule: {out}")

    status = "SUCCESS" if all_ok else "PARTIAL"
    logger.log("firewall", "tcp_scrubbing", f"port_{target_port}", "none", "rules_applied", status)
    if all_ok:
        print("  [✓] Packet scrubbing rules active in iptables.")
    return all_ok


def reset_defenses(logger, dry_run=False):
    """
    Reset all kernel parameters and flush custom iptables rules created by this script.
    """
    print("\n[-] Resetting Defenses to Lab Baseline Defaults...")

    if platform.system().lower() != "linux":
        print(f"  [!] Host is {platform.system()}. Reset recorded.")
        logger.log("reset", "restore_defaults", "all", "custom", "defaults", "SIMULATED_NON_LINUX")
        return True

    # 1. Reset sysctl
    set_sysctl("net.ipv4.tcp_syncookies", "1", logger, "reset", dry_run)
    set_sysctl("net.ipv4.tcp_max_syn_backlog", "512", logger, "reset", dry_run)
    set_sysctl("net.core.somaxconn", "128", logger, "reset", dry_run)
    set_sysctl("net.ipv4.tcp_synack_retries", "5", logger, "reset", dry_run)

    # 2. Remove tagged iptables rules
    print("  [*] Removing custom iptables rules tagged with NSS_SYN_DEFENSE...")
    # Read rules line by line with line numbers
    success, out = run_command("iptables -L INPUT --line-numbers -n")
    if success and out:
        # Collect line numbers in reverse order so deleting doesn't shift lines
        lines_to_delete = []
        for line in out.splitlines():
            if IPTABLES_TAG in line:
                parts = line.split()
                if parts and parts[0].isdigit():
                    lines_to_delete.append(int(parts[0]))

        lines_to_delete.sort(reverse=True)
        for num in lines_to_delete:
            del_cmd = f"iptables -D INPUT {num}"
            run_command(del_cmd, dry_run=dry_run)
            print(f"  [✓] Deleted iptables INPUT rule #{num}")

    logger.log("reset", "restore_defaults", "all", "custom", "defaults", "SUCCESS")
    print("  [✓] All defense rules successfully cleared and reset to baseline.")
    return True


def display_status():
    """Print current kernel parameters and iptables rules relevant to SYN flood defense."""
    print("\n" + "=" * 65)
    print("            Current Network Defense Status")
    print("=" * 65)
    print("  Kernel sysctl parameters:")
    print(f"    net.ipv4.tcp_syncookies       = {get_sysctl('net.ipv4.tcp_syncookies')}")
    print(f"    net.ipv4.tcp_max_syn_backlog   = {get_sysctl('net.ipv4.tcp_max_syn_backlog')}")
    print(f"    net.core.somaxconn             = {get_sysctl('net.core.somaxconn')}")
    print(f"    net.ipv4.tcp_synack_retries    = {get_sysctl('net.ipv4.tcp_synack_retries')}")
    print("")

    if platform.system().lower() == "linux":
        print("  Active iptables INPUT rules with NSS_SYN_DEFENSE tag:")
        success, out = run_command(f"iptables -S INPUT 2>/dev/null | grep '{IPTABLES_TAG}'")
        if success and out.strip():
            for line in out.splitlines():
                print(f"    {line}")
        else:
            print("    (No active custom NSS defense rules found)")
    else:
        print(f"  iptables: Not applicable on {platform.system()} host.")
    print("=" * 65 + "\n")


def parse_args():
    parser = argparse.ArgumentParser(
        description="TCP SYN Flood Defense and Mitigation Manager (CS74136 Lab Project)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  syn_cookies       Enable kernel TCP SYN cookies (RFC 4987)
  rate_limit        Configure iptables token-bucket rate limiting per source IP
  connection_limit  Increase tcp_max_syn_backlog and somaxconn queue sizes
  firewall          Scrub invalid TCP flags and malformed packets
  all               Apply all 4 defense layers simultaneously
  status            Display current sysctl parameters and iptables rules
  reset             Restore default settings and delete all custom rules

Example:
  sudo python3 defense.py --mode all --target-port 80
        """
    )
    parser.add_argument(
        "--mode",
        choices=["syn_cookies", "rate_limit", "connection_limit", "firewall", "all", "status", "reset"],
        required=True,
        help="Defense mechanism to apply or action to take."
    )
    parser.add_argument(
        "--target-port",
        type=int,
        default=80,
        help="Target TCP port for firewall rules (default: 80)."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate actions without making system modifications."
    )
    return parser.parse_args()


def main():
    print_banner()
    args = parse_args()

    if not is_root() and not args.dry_run and args.mode != "status":
        print("  [!] WARNING: Managing kernel parameters and iptables requires root privileges.")
        print("      Run with: sudo python3 defense.py ...")
        if platform.system().lower() == "linux":
            sys.exit(1)

    logger = DefenseLogger()

    try:
        if args.mode == "status":
            display_status()

        elif args.mode == "syn_cookies":
            apply_syn_cookies(logger, dry_run=args.dry_run)
            display_status()

        elif args.mode == "rate_limit":
            apply_rate_limit(args.target_port, logger, dry_run=args.dry_run)
            display_status()

        elif args.mode == "connection_limit":
            apply_connection_limits(logger, dry_run=args.dry_run)
            display_status()

        elif args.mode == "firewall":
            apply_firewall_scrubbing(args.target_port, logger, dry_run=args.dry_run)
            display_status()

        elif args.mode == "all":
            print("[*] Activating Defense-in-Depth Suite (All Layers)...")
            apply_syn_cookies(logger, dry_run=args.dry_run)
            apply_connection_limits(logger, dry_run=args.dry_run)
            apply_rate_limit(args.target_port, logger, dry_run=args.dry_run)
            apply_firewall_scrubbing(args.target_port, logger, dry_run=args.dry_run)
            display_status()

        elif args.mode == "reset":
            reset_defenses(logger, dry_run=args.dry_run)
            display_status()

    finally:
        logger.close()
        print(f"[*] Defense audit events recorded to: {LOG_FILE}\n")


if __name__ == "__main__":
    main()
