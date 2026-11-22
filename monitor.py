#!/usr/bin/env python3
"""
monitor.py — Real-Time Network Monitor for SYN Flood Observation
=================================================================
Course  : CS74136 Network and System Security, NIT Patna
Project : Bounded TCP SYN Flooding and Resilience Testing (Project d)

PURPOSE
-------
This script passively **sniffs** network traffic on a chosen interface and
produces a **live dashboard** showing TCP packet statistics.  It is designed
to run alongside `syn_flood.py` (the attacker) and `target_server.py` (the
victim) so the lab operator can watch the attack unfold in real-time.

It answers questions like:
  - How many SYN packets per second is the attacker sending?
  - Is the server replying with SYN-ACK (i.e., is its backlog still open)?
  - How many RST packets appear (rejected connections)?
  - How many connections are half-open vs. fully established?

BACKGROUND — TCP Flags and Connection States
---------------------------------------------
Every TCP segment carries a set of **flags** in its header:

  Flag  Bit   Meaning
  ───── ───── ───────────────────────────────────────────────────
  SYN   0x02  Synchronize — initiates a connection (step 1)
  ACK   0x10  Acknowledge — confirms receipt of data
  RST   0x04  Reset — abruptly tears down a connection
  FIN   0x01  Finish — gracefully closes a connection
  PSH   0x08  Push — deliver data to the application immediately

A **normal** three-way handshake looks like:

    Client               Server
      |---- SYN -------->|       flags = 0x02  (S)
      |<--- SYN+ACK -----|       flags = 0x12  (SA)
      |---- ACK -------->|       flags = 0x10  (A)
      |     ESTABLISHED  |

A **SYN flood** skips the final ACK.  The server's side stays in the
**SYN_RECEIVED** state, consuming a slot in its backlog queue.  When the
queue is full, subsequent SYNs are silently dropped or answered with RST,
and legitimate users see connection timeouts.

This monitor classifies every packet it sees and maintains running counters
so you can observe these dynamics.

HALF-OPEN CONNECTION ESTIMATION
-------------------------------
We approximate the number of half-open connections as:

    half_open ≈ SYN_count − SYN-ACK_count − RST_from_server

This works because:
  - Every SYN that gets a SYN-ACK has at least progressed past the first step.
  - Every RST from the server means the connection was rejected (backlog full
    or no listener).
  - SYNs with no corresponding SYN-ACK or RST are stuck in the server's
    SYN queue → half-open.

The estimate is imperfect (we may miss packets, or the monitor may start
after some SYNs were already sent), but it gives a useful real-time indicator.

USAGE
-----
    sudo python monitor.py --target-ip 192.168.72.130 --target-port 80 --duration 60

Requires Scapy and administrator/root privileges to capture raw packets.

Authors : NSS Project Team, CS74136
"""

import argparse
import csv
import datetime
import os
import signal
import sys
import threading
import time

try:
    from scapy.all import sniff, TCP, IP, conf
except ImportError:
    print("[!] Scapy is not installed. Install it with:")
    print("    pip install scapy")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Constants — TCP Flag Masks
# ─────────────────────────────────────────────────────────────────────────────
# TCP flags are stored as an 8-bit field in the TCP header.
# Scapy exposes them via pkt[TCP].flags as a FlagValue or int.

FLAG_FIN = 0x01
FLAG_SYN = 0x02
FLAG_RST = 0x04
FLAG_PSH = 0x08
FLAG_ACK = 0x10
FLAG_URG = 0x20

BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║        NETWORK MONITOR — SYN Flood Observation Tool         ║
║          CS74136 Network and System Security, NITP          ║
╠══════════════════════════════════════════════════════════════╣
║  Passively captures TCP packets to/from the target server.  ║
║  Requires root / admin privileges for raw packet capture.   ║
╚══════════════════════════════════════════════════════════════╝
"""


# ─────────────────────────────────────────────────────────────────────────────
# Packet Statistics Tracker
# ─────────────────────────────────────────────────────────────────────────────

class PacketStats:
    """Thread-safe container for real-time packet counters.

    TCP Connection State Tracking
    -----------------------------
    We maintain a simplified view of connection states by tracking unique
    (src_ip, src_port, dst_ip, dst_port) tuples and the last flag combination
    seen for each.

    States we track:
      SYN_SENT      — We saw a SYN from client to server (no response yet)
      SYN_RECEIVED  — Server replied SYN-ACK (waiting for client's ACK)
      ESTABLISHED   — We saw the final ACK completing the handshake
      RESET         — A RST was seen, connection torn down
      CLOSED        — FIN exchange observed
    """

    def __init__(self):
        self.lock = threading.Lock()

        # ── Aggregate counters ────────────────────────────────────────────
        self.total_syn = 0          # SYN packets (no ACK flag)
        self.total_syn_ack = 0      # SYN+ACK packets (server replies)
        self.total_ack = 0          # Pure ACK packets
        self.total_rst = 0          # RST packets (connection aborts)
        self.total_fin = 0          # FIN packets (graceful close)
        self.total_other = 0        # Anything else (PSH+ACK, etc.)
        self.total_packets = 0      # Grand total

        # ── Rate tracking ─────────────────────────────────────────────────
        # We store timestamps of SYN packets in the last window to compute
        # an instantaneous rate.
        self.syn_timestamps = []     # list of time.time() values
        self.rate_window = 5.0       # seconds to average over

        # ── Connection state table ────────────────────────────────────────
        # Key: (src_ip, src_port, dst_ip, dst_port)   Value: state string
        self.connections = {}

        # ── Time-series for CSV ───────────────────────────────────────────
        # Every snapshot interval we append a row:
        #   (timestamp, syn, syn_ack, ack, rst, fin, other, syn_rate,
        #    half_open, total)
        self.timeseries = []

        self.start_time = time.time()

    # ── Packet classification ─────────────────────────────────────────────

    def record_packet(self, flags: int, src_ip: str, src_port: int,
                      dst_ip: str, dst_port: int, target_ip: str):
        """Classify a TCP packet by its flags and update counters.

        Parameters
        ----------
        flags      : int — raw TCP flags field
        src_ip     : str — source IP address
        src_port   : int — source TCP port
        dst_ip     : str — destination IP address
        dst_port   : int — destination TCP port
        target_ip  : str — the victim server's IP (used to determine
                           direction: toward server vs. from server)
        """
        now = time.time()

        with self.lock:
            self.total_packets += 1

            is_syn     = bool(flags & FLAG_SYN)
            is_ack     = bool(flags & FLAG_ACK)
            is_rst     = bool(flags & FLAG_RST)
            is_fin     = bool(flags & FLAG_FIN)

            # ── Classify the packet ──────────────────────────────────────
            if is_syn and not is_ack:
                # Pure SYN — a connection initiation attempt.
                # In a SYN flood, the attacker sends millions of these with
                # spoofed source IPs.
                self.total_syn += 1
                self.syn_timestamps.append(now)

                # Track connection state
                key = (src_ip, src_port, dst_ip, dst_port)
                self.connections[key] = "SYN_SENT"

            elif is_syn and is_ack:
                # SYN+ACK — the server's response to a SYN.
                # This means the server still has room in its backlog and is
                # allocating a TCB (Transmission Control Block) for this
                # connection.  During a successful flood, these will decrease
                # or stop entirely as the backlog fills.
                self.total_syn_ack += 1

                # The connection key from the server's perspective is reversed.
                key = (dst_ip, dst_port, src_ip, src_port)
                self.connections[key] = "SYN_RECEIVED"

            elif is_rst:
                # RST — connection reset.
                # Servers send RST when their backlog overflows, or when they
                # receive an ACK for a connection they don't remember (e.g.,
                # because it was already timed out).
                # Attackers' spoofed machines also send RST when they receive
                # an unexpected SYN-ACK (since they never sent a SYN).
                self.total_rst += 1

                # Mark connection as RESET in whichever direction we find it
                key_fwd = (src_ip, src_port, dst_ip, dst_port)
                key_rev = (dst_ip, dst_port, src_ip, src_port)
                if key_fwd in self.connections:
                    self.connections[key_fwd] = "RESET"
                elif key_rev in self.connections:
                    self.connections[key_rev] = "RESET"

            elif is_fin:
                # FIN — graceful connection teardown.
                self.total_fin += 1

                key_fwd = (src_ip, src_port, dst_ip, dst_port)
                key_rev = (dst_ip, dst_port, src_ip, src_port)
                if key_fwd in self.connections:
                    self.connections[key_fwd] = "CLOSED"
                elif key_rev in self.connections:
                    self.connections[key_rev] = "CLOSED"

            elif is_ack and not is_syn:
                # Pure ACK — could be the final step of the three-way
                # handshake (SYN → SYN-ACK → ACK) or normal data transfer.
                self.total_ack += 1

                key = (src_ip, src_port, dst_ip, dst_port)
                key_rev = (dst_ip, dst_port, src_ip, src_port)
                # Promote SYN_RECEIVED → ESTABLISHED (handshake complete)
                if self.connections.get(key) == "SYN_RECEIVED":
                    self.connections[key] = "ESTABLISHED"
                elif self.connections.get(key_rev) == "SYN_RECEIVED":
                    self.connections[key_rev] = "ESTABLISHED"
            else:
                self.total_other += 1

            # ── Prune old SYN timestamps outside the rate window ─────────
            cutoff = now - self.rate_window
            self.syn_timestamps = [t for t in self.syn_timestamps
                                   if t > cutoff]

    # ── Computed metrics ──────────────────────────────────────────────────

    def syn_rate(self) -> float:
        """SYN packets per second over the last `rate_window` seconds."""
        with self.lock:
            now = time.time()
            cutoff = now - self.rate_window
            recent = [t for t in self.syn_timestamps if t > cutoff]
            if len(recent) < 2:
                return float(len(recent)) / self.rate_window
            span = recent[-1] - recent[0]
            if span == 0:
                return float(len(recent))
            return len(recent) / span

    def half_open_estimate(self) -> int:
        """Estimate the number of half-open connections.

        A connection is half-open if we saw a SYN to the server but have not
        seen a corresponding completed handshake (ESTABLISHED) or teardown
        (RESET / CLOSED).  Concretely, connections in SYN_SENT or
        SYN_RECEIVED state.
        """
        with self.lock:
            return sum(1 for st in self.connections.values()
                       if st in ("SYN_SENT", "SYN_RECEIVED"))

    def state_distribution(self) -> dict:
        """Count connections in each state."""
        with self.lock:
            dist = {}
            for st in self.connections.values():
                dist[st] = dist.get(st, 0) + 1
            return dist

    def snapshot(self) -> dict:
        """Return a consistent copy of all counters."""
        with self.lock:
            return {
                "total_packets": self.total_packets,
                "syn":           self.total_syn,
                "syn_ack":       self.total_syn_ack,
                "ack":           self.total_ack,
                "rst":           self.total_rst,
                "fin":           self.total_fin,
                "other":         self.total_other,
                "elapsed":       time.time() - self.start_time,
            }

    def take_timeseries_row(self):
        """Build one row for the CSV timeseries and append internally."""
        snap = self.snapshot()
        row = {
            "timestamp":    datetime.datetime.now().isoformat(
                                timespec="milliseconds"),
            "elapsed_s":    round(snap["elapsed"], 1),
            "syn":          snap["syn"],
            "syn_ack":      snap["syn_ack"],
            "ack":          snap["ack"],
            "rst":          snap["rst"],
            "fin":          snap["fin"],
            "other":        snap["other"],
            "total":        snap["total_packets"],
            "syn_rate":     round(self.syn_rate(), 1),
            "half_open":    self.half_open_estimate(),
        }
        with self.lock:
            self.timeseries.append(row)
        return row


# ─────────────────────────────────────────────────────────────────────────────
# Live Dashboard
# ─────────────────────────────────────────────────────────────────────────────

def clear_screen():
    """Cross-platform terminal clear."""
    os.system("cls" if os.name == "nt" else "clear")


def render_dashboard(pstats: PacketStats, target_ip: str, target_port: int,
                     duration: int):
    """Print a full-screen dashboard with current statistics.

    The dashboard refreshes every 2 seconds and shows:
      - Current SYN rate (packets/sec)
      - Cumulative packet counts by type
      - Estimated half-open connections
      - Connection state distribution
      - Mini timeline of recent SYN rates
    """
    clear_screen()
    snap = pstats.snapshot()
    rate = pstats.syn_rate()
    half_open = pstats.half_open_estimate()
    states = pstats.state_distribution()
    elapsed = snap["elapsed"]
    remaining = max(0, duration - elapsed) if duration > 0 else float("inf")

    elapsed_str = time.strftime("%H:%M:%S", time.gmtime(elapsed))
    if duration > 0:
        remaining_str = time.strftime("%H:%M:%S", time.gmtime(remaining))
    else:
        remaining_str = "∞"

    print("=" * 64)
    print("     LIVE NETWORK MONITOR — SYN Flood Observation Dashboard")
    print("=" * 64)
    print(f"  Target       : {target_ip}:{target_port}")
    print(f"  Elapsed      : {elapsed_str}    Remaining: {remaining_str}")
    print("-" * 64)
    print(f"  Current SYN Rate : {rate:>8.1f} pkt/s")
    print(f"  Half-Open (est.) : {half_open:>8}")
    print("-" * 64)
    print("  PACKET COUNTS")
    print(f"    SYN            : {snap['syn']:>10}")
    print(f"    SYN-ACK        : {snap['syn_ack']:>10}")
    print(f"    ACK            : {snap['ack']:>10}")
    print(f"    RST            : {snap['rst']:>10}")
    print(f"    FIN            : {snap['fin']:>10}")
    print(f"    Other          : {snap['other']:>10}")
    print(f"    ─────────────────────────────")
    print(f"    Total          : {snap['total_packets']:>10}")
    print("-" * 64)
    print("  CONNECTION STATES")
    if states:
        for state, count in sorted(states.items()):
            bar = "█" * min(count, 40)
            print(f"    {state:<16}: {count:>6}  {bar}")
    else:
        print("    (none observed yet)")
    print("-" * 64)

    # ── Mini SYN-rate timeline ────────────────────────────────────────────
    # Show the last 10 timeseries samples as a simple bar chart.
    with pstats.lock:
        recent = pstats.timeseries[-10:]
    if recent:
        print("  SYN RATE TIMELINE (last samples)")
        max_rate = max(r["syn_rate"] for r in recent) or 1
        for r in recent:
            bar_len = int((r["syn_rate"] / max_rate) * 30) if max_rate else 0
            bar = "▓" * bar_len
            print(f"    {r['elapsed_s']:>7.1f}s │ {r['syn_rate']:>7.1f} │ {bar}")
    print("=" * 64)
    print("  Press Ctrl+C to stop monitoring.")


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard refresh thread
# ─────────────────────────────────────────────────────────────────────────────

def dashboard_thread(pstats: PacketStats, target_ip: str, target_port: int,
                     duration: int, stop_event: threading.Event):
    """Refresh the dashboard every 2 seconds and record timeseries data."""
    while not stop_event.is_set():
        pstats.take_timeseries_row()
        render_dashboard(pstats, target_ip, target_port, duration)
        stop_event.wait(2.0)


# ─────────────────────────────────────────────────────────────────────────────
# Packet callback
# ─────────────────────────────────────────────────────────────────────────────

def make_packet_callback(pstats: PacketStats, target_ip: str):
    """Return a Scapy callback that records every TCP packet.

    Scapy invokes this callback for each captured packet that matches the
    BPF filter.  We extract the IP and TCP layers and pass them to the
    PacketStats tracker.
    """
    def callback(pkt):
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            return

        ip_layer  = pkt[IP]
        tcp_layer = pkt[TCP]

        flags    = int(tcp_layer.flags)
        src_ip   = ip_layer.src
        dst_ip   = ip_layer.dst
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport

        pstats.record_packet(flags, src_ip, src_port,
                             dst_ip, dst_port, target_ip)

    return callback


# ─────────────────────────────────────────────────────────────────────────────
# CSV export
# ─────────────────────────────────────────────────────────────────────────────

TIMESERIES_HEADER = [
    "timestamp", "elapsed_s", "syn", "syn_ack", "ack", "rst", "fin",
    "other", "total", "syn_rate", "half_open"
]


def save_csv(pstats: PacketStats, path: str):
    """Write all collected timeseries rows to a CSV file."""
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=TIMESERIES_HEADER)
        writer.writeheader()
        with pstats.lock:
            for row in pstats.timeseries:
                writer.writerow(row)
    print(f"[*] Monitoring data saved to {path}")


# ─────────────────────────────────────────────────────────────────────────────
# Summary report
# ─────────────────────────────────────────────────────────────────────────────

def print_summary(pstats: PacketStats):
    """Print a final summary table after monitoring ends.

    Understanding the Summary
    -------------------------
    - **SYN count** shows how many connection attempts (or attack packets)
      were observed.
    - **SYN-ACK count** shows how many the server was able to respond to.
      If this is much lower than SYN, the server's backlog was likely full.
    - **RST count** indicates connections that were forcibly torn down —
      either the server rejecting connections (backlog full) or spoofed-IP
      machines rejecting unexpected SYN-ACKs.
    - **Half-open estimate** shows how many connections were stuck waiting
      for the final ACK that never came — the core effect of a SYN flood.
    - **ACK count** tells you how many handshakes actually completed.
      A low ACK count relative to SYN means legitimate connections are
      being starved.
    """
    snap = pstats.snapshot()
    states = pstats.state_distribution()
    elapsed_str = time.strftime("%H:%M:%S", time.gmtime(snap["elapsed"]))
    avg_syn_rate = (snap["syn"] / snap["elapsed"]) if snap["elapsed"] > 0 else 0

    print("\n")
    print("=" * 64)
    print("          MONITORING SESSION — FINAL SUMMARY")
    print("=" * 64)
    print(f"  Duration             : {elapsed_str}")
    print(f"  Total packets        : {snap['total_packets']}")
    print("-" * 64)
    print("  PACKET BREAKDOWN")
    print(f"    SYN                : {snap['syn']:>10}")
    print(f"    SYN-ACK            : {snap['syn_ack']:>10}")
    print(f"    ACK                : {snap['ack']:>10}")
    print(f"    RST                : {snap['rst']:>10}")
    print(f"    FIN                : {snap['fin']:>10}")
    print(f"    Other              : {snap['other']:>10}")
    print("-" * 64)
    print("  DERIVED METRICS")
    print(f"    Avg SYN rate       : {avg_syn_rate:>10.1f} pkt/s")
    half_open = pstats.half_open_estimate()
    print(f"    Half-open (final)  : {half_open:>10}")
    print("-" * 64)
    print("  FINAL CONNECTION STATES")
    if states:
        for state, count in sorted(states.items()):
            print(f"    {state:<18}: {count:>6}")
    else:
        print("    (no connections tracked)")
    print("=" * 64)


# ─────────────────────────────────────────────────────────────────────────────
# Main monitor loop
# ─────────────────────────────────────────────────────────────────────────────

def run_monitor(target_ip: str, target_port: int, interface: str,
                duration: int, log_path: str):
    """Start packet capture and the live dashboard.

    BPF Filter
    ----------
    We use a Berkeley Packet Filter (BPF) expression to tell the kernel to
    deliver only TCP traffic involving the target IP and port.  This reduces
    the amount of traffic Scapy has to process (important on busy networks).

        "tcp and host <ip> and port <port>"

    Scapy then calls our callback for every matching packet.
    """
    pstats = PacketStats()

    # Build BPF filter — capture only TCP traffic to/from the target
    bpf_filter = f"tcp and host {target_ip} and port {target_port}"

    print(BANNER)
    print(f"[*] Target     : {target_ip}:{target_port}")
    print(f"[*] Interface  : {interface or 'default'}")
    print(f"[*] BPF filter : {bpf_filter}")
    print(f"[*] Duration   : {duration}s" if duration > 0 else
          "[*] Duration   : unlimited (Ctrl+C to stop)")
    print(f"[*] Log file   : {log_path}")
    print("[*] Starting capture...\n")

    # ── Start dashboard thread ────────────────────────────────────────────
    stop_event = threading.Event()
    dash = threading.Thread(target=dashboard_thread,
                            args=(pstats, target_ip, target_port,
                                  duration, stop_event),
                            daemon=True)
    dash.start()

    # ── Packet capture ────────────────────────────────────────────────────
    # Scapy's sniff() blocks until `timeout` expires or `stop_filter` returns
    # True.  We run it in the main thread and handle Ctrl+C.
    callback = make_packet_callback(pstats, target_ip)

    sniff_kwargs = {
        "prn":          callback,
        "filter":       bpf_filter,
        "store":        False,          # don't keep packets in memory
    }

    if interface:
        sniff_kwargs["iface"] = interface

    if duration > 0:
        sniff_kwargs["timeout"] = duration

    try:
        sniff(**sniff_kwargs)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("\n[!] Permission denied. Raw packet capture requires "
              "administrator / root privileges.")
        print("    Try: sudo python3 monitor.py ...")
        sys.exit(1)
    finally:
        stop_event.set()
        dash.join(timeout=3)

        # Take one last timeseries sample
        pstats.take_timeseries_row()

        # Save CSV and print summary
        save_csv(pstats, log_path)
        print_summary(pstats)


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Real-time network monitor for observing SYN flood "
                    "attacks (CS74136 NSS Lab, NIT Patna).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python monitor.py --target-ip 192.168.72.130 "
            "--target-port 80 --duration 60\n"
            "  sudo python monitor.py --target-ip 10.0.0.5 "
            "--target-port 8080 --interface eth0\n"
        )
    )
    parser.add_argument(
        "--target-ip", type=str, required=True,
        help="IP address of the victim server to monitor."
    )
    parser.add_argument(
        "--target-port", type=int, default=80,
        help="TCP port of the victim server (default: 80)."
    )
    parser.add_argument(
        "--interface", type=str, default=None,
        help="Network interface to sniff on (e.g., eth0, ens33). "
             "If omitted, Scapy uses the default interface."
    )
    parser.add_argument(
        "--duration", type=int, default=0,
        help="Monitoring duration in seconds (default: 0 = unlimited, "
             "stop with Ctrl+C)."
    )
    parser.add_argument(
        "--log", type=str, default="monitor_log.csv",
        help="Path to the CSV log file (default: monitor_log.csv)."
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_monitor(
        target_ip=args.target_ip,
        target_port=args.target_port,
        interface=args.interface,
        duration=args.duration,
        log_path=args.log,
    )
