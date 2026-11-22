#!/usr/bin/env python3
"""
target_server.py — Simple TCP Victim Server for SYN Flood Resilience Testing
=============================================================================
Course  : CS74136 Network and System Security, NIT Patna
Project : Bounded TCP SYN Flooding and Resilience Testing (Project d)

PURPOSE
-------
This script acts as the **victim** in a controlled SYN flood experiment.  It is
a minimal TCP server that:

  1. Listens on a configurable port and accepts incoming connections.
  2. Responds with an HTTP 200 "Server is alive" message.
  3. Enforces a configurable backlog / max-connections limit to simulate a real
     server whose resources can be exhausted.
  4. Logs every connection event (accept, close, refuse) to a CSV file for
     later analysis.
  5. Prints live statistics so the operator can watch the impact of an attack
     in real-time.

BACKGROUND — TCP Three-Way Handshake & SYN Flooding
----------------------------------------------------
Normal TCP connection setup uses a **three-way handshake**:

    Client              Server
      |---- SYN -------->|      (1) Client sends SYN with random seq number
      |<--- SYN-ACK -----|      (2) Server allocates resources, replies SYN-ACK
      |---- ACK -------->|      (3) Client confirms; connection is ESTABLISHED

The server **allocates memory** (a Transmission Control Block, TCB) at step 2
and places the half-open connection in its **SYN queue** (also called the
backlog).  If the client never sends the final ACK (step 3), the half-open
connection sits in the queue until a timer expires (typically 75 s).

A **SYN flood attack** exploits this by sending thousands of SYN packets with
spoofed source IPs.  The server responds with SYN-ACKs that go nowhere, and
its SYN queue fills up.  Once the queue is full the server cannot accept
*any* new connections — legitimate users are denied service.

This server simulates that behaviour with the `--max-connections` flag: once
the limit is reached, further connections are immediately closed (refused).

USAGE
-----
    python target_server.py --port 80 --max-connections 100

WARNING: Run only inside an isolated lab network.

Authors : NSS Project Team, CS74136
"""

import argparse
import csv
import datetime
import os
import signal
import socket
import sys
import threading
import time


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

HTTP_RESPONSE = (
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/plain\r\n"
    "Connection: close\r\n"
    "\r\n"
    "Server is alive\r\n"
)

BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║           TARGET SERVER — SYN Flood Resilience Lab          ║
║          CS74136 Network and System Security, NITP          ║
╠══════════════════════════════════════════════════════════════╣
║  This server is intentionally simple.  It is designed to    ║
║  be targeted by a CONTROLLED SYN flood inside an isolated   ║
║  lab environment.  Do NOT expose it to the Internet.        ║
╚══════════════════════════════════════════════════════════════╝
"""


# ─────────────────────────────────────────────────────────────────────────────
# Global statistics (thread-safe via a lock)
# ─────────────────────────────────────────────────────────────────────────────

class ServerStats:
    """Thread-safe container for connection statistics.

    Why thread-safe?
    ----------------
    Each accepted connection is handled in its own thread.  Multiple threads
    may update counters concurrently, so we guard writes with a Lock.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.active_connections = 0       # connections currently open
        self.total_accepted = 0           # lifetime accepted connections
        self.total_refused = 0            # connections closed because limit hit
        self.total_closed_normally = 0    # connections that completed normally
        self.start_time = time.time()

    def accept(self):
        with self.lock:
            self.active_connections += 1
            self.total_accepted += 1
            return self.active_connections

    def close_normal(self):
        with self.lock:
            self.active_connections = max(0, self.active_connections - 1)
            self.total_closed_normally += 1
            return self.active_connections

    def refuse(self):
        with self.lock:
            self.total_refused += 1

    def snapshot(self):
        """Return a consistent copy of all counters."""
        with self.lock:
            return {
                "active":    self.active_connections,
                "accepted":  self.total_accepted,
                "refused":   self.total_refused,
                "closed":    self.total_closed_normally,
                "uptime":    time.time() - self.start_time,
            }


stats = ServerStats()

# ─────────────────────────────────────────────────────────────────────────────
# CSV Logger
# ─────────────────────────────────────────────────────────────────────────────

class CSVLogger:
    """Appends connection events to `server_log.csv`.

    Each row records:
        timestamp, client_ip, client_port, event_type, active_connections

    Event types: ACCEPT, CLOSE, REFUSE, SERVER_START, SERVER_STOP
    """

    HEADER = ["timestamp", "client_ip", "client_port", "event_type",
              "active_connections"]

    def __init__(self, path="server_log.csv"):
        self.path = path
        self.lock = threading.Lock()
        # Write header if file is new
        write_header = not os.path.exists(path)
        self._file = open(path, "a", newline="", buffering=1)
        self._writer = csv.writer(self._file)
        if write_header:
            self._writer.writerow(self.HEADER)

    def log(self, client_ip, client_port, event_type, active_connections):
        ts = datetime.datetime.now().isoformat(timespec="milliseconds")
        with self.lock:
            self._writer.writerow([ts, client_ip, client_port,
                                   event_type, active_connections])

    def close(self):
        self._file.close()


# ─────────────────────────────────────────────────────────────────────────────
# Connection handler
# ─────────────────────────────────────────────────────────────────────────────

def handle_client(conn: socket.socket, addr: tuple, logger: CSVLogger,
                  max_conn: int):
    """Handle a single accepted TCP connection.

    TCP State Perspective
    ---------------------
    By the time this function is called, the kernel has already completed the
    three-way handshake (SYN → SYN-ACK → ACK).  The connection is in the
    ESTABLISHED state.

    If the server's accept-queue was full (controlled here by `max_conn`), the
    kernel would have silently dropped the incoming SYN or sent a RST,
    depending on the OS settings.  We simulate this at the application level
    by immediately closing the socket when the active count exceeds the limit.
    """
    client_ip, client_port = addr

    # --- Check capacity -------------------------------------------------------
    # The real kernel backlog has a similar concept: `listen(fd, backlog)`.
    # When the backlog overflows, new SYNs are dropped → the client sees a
    # timeout, which is exactly the denial-of-service effect of a SYN flood.
    active = stats.accept()

    if active > max_conn:
        # Over capacity — refuse the connection
        stats.close_normal()          # decrement active count
        stats.refuse()
        logger.log(client_ip, client_port, "REFUSE", active - 1)
        try:
            conn.close()
        except OSError:
            pass
        return

    logger.log(client_ip, client_port, "ACCEPT", active)

    try:
        # Send a minimal HTTP response so we can verify that completed
        # connections actually transfer data (useful when comparing against
        # half-open SYN-flood connections that never reach this point).
        conn.settimeout(5.0)       # don't hang forever on a dead client
        conn.sendall(HTTP_RESPONSE.encode())
    except (BrokenPipeError, ConnectionResetError, OSError):
        # Client vanished (common during a SYN flood with spoofed IPs).
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass
        remaining = stats.close_normal()
        logger.log(client_ip, client_port, "CLOSE", remaining)


# ─────────────────────────────────────────────────────────────────────────────
# Live stats display
# ─────────────────────────────────────────────────────────────────────────────

def stats_display_thread(stop_event: threading.Event):
    """Print a live stats line every 2 seconds.

    This lets the lab operator watch the attack's impact without opening a
    separate monitoring tool.
    """
    while not stop_event.is_set():
        s = stats.snapshot()
        uptime_str = time.strftime("%H:%M:%S", time.gmtime(s["uptime"]))
        line = (
            f"\r[{uptime_str}]  "
            f"Active: {s['active']:>5}  |  "
            f"Accepted: {s['accepted']:>7}  |  "
            f"Refused: {s['refused']:>7}  |  "
            f"Closed: {s['closed']:>7}"
        )
        sys.stdout.write(line)
        sys.stdout.flush()
        stop_event.wait(2.0)


# ─────────────────────────────────────────────────────────────────────────────
# Main server loop
# ─────────────────────────────────────────────────────────────────────────────

def run_server(port: int, max_connections: int, log_path: str):
    """Bind, listen, and accept connections in a loop.

    Listening & the Backlog
    -----------------------
    `socket.listen(backlog)` tells the kernel how many **pending** (half-open)
    connections to queue before it starts dropping SYNs.  In this educational
    server we pass a small backlog value equal to `max_connections` so that
    the queue fills up quickly during a flood.

    Each accepted connection is dispatched to a separate thread so the main
    thread can keep calling `accept()`.
    """
    logger = CSVLogger(log_path)

    # Create a TCP (SOCK_STREAM) socket using IPv4 (AF_INET).
    # TCP is the transport layer protocol whose handshake the SYN flood abuses.
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # SO_REUSEADDR lets us restart the server quickly without waiting for the
    # OS TIME_WAIT period to expire (useful during repeated lab experiments).
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_sock.bind(("0.0.0.0", port))
    except PermissionError:
        print(f"[!] Permission denied binding to port {port}.")
        print("    Ports below 1024 require administrator / root privileges.")
        print("    Try: sudo python3 target_server.py --port 8080")
        sys.exit(1)
    except OSError as e:
        print(f"[!] Cannot bind to port {port}: {e}")
        sys.exit(1)

    # The backlog parameter limits the kernel's SYN / accept queue.
    # A small value means the queue saturates faster under a flood.
    server_sock.listen(min(max_connections, 128))
    server_sock.settimeout(1.0)  # periodically wake up to check stop flag

    logger.log("-", "-", "SERVER_START", 0)
    print(BANNER)
    print(f"[*] Listening on 0.0.0.0:{port}")
    print(f"[*] Max connections: {max_connections}")
    print(f"[*] Logging to: {log_path}")
    print(f"[*] Press Ctrl+C to stop.\n")

    # Start the live-stats printer
    stop_event = threading.Event()
    display_t = threading.Thread(target=stats_display_thread,
                                 args=(stop_event,), daemon=True)
    display_t.start()

    try:
        while True:
            try:
                conn, addr = server_sock.accept()
                # Dispatch each connection to its own thread.
                # In production servers this would be a thread pool or
                # async I/O; here simplicity is more important.
                t = threading.Thread(target=handle_client,
                                     args=(conn, addr, logger, max_connections),
                                     daemon=True)
                t.start()
            except socket.timeout:
                # accept() timed out — just loop and check for Ctrl+C
                continue
            except OSError:
                # Socket was closed during shutdown
                break

    except KeyboardInterrupt:
        pass
    finally:
        # ── Graceful shutdown ─────────────────────────────────────────────
        stop_event.set()
        display_t.join(timeout=3)
        server_sock.close()

        s = stats.snapshot()
        logger.log("-", "-", "SERVER_STOP", s["active"])
        logger.close()

        uptime_str = time.strftime("%H:%M:%S", time.gmtime(s["uptime"]))

        print("\n")
        print("=" * 60)
        print("              SERVER SHUTDOWN — SUMMARY")
        print("=" * 60)
        print(f"  Uptime              : {uptime_str}")
        print(f"  Total accepted      : {s['accepted']}")
        print(f"  Total refused       : {s['refused']}")
        print(f"  Closed normally     : {s['closed']}")
        print(f"  Still active at stop: {s['active']}")
        print(f"  Log file            : {log_path}")
        print("=" * 60)
        print("[*] Server stopped.")


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Target TCP server for SYN flood resilience testing "
                    "(CS74136 NSS Lab, NIT Patna).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python target_server.py --port 8080\n"
            "  python target_server.py --port 80 --max-connections 50\n"
        )
    )
    parser.add_argument(
        "--port", type=int, default=80,
        help="TCP port to listen on (default: 80). Ports < 1024 need root."
    )
    parser.add_argument(
        "--max-connections", type=int, default=100,
        help="Maximum simultaneous connections before refusing new ones "
             "(default: 100). Simulates the kernel backlog limit."
    )
    parser.add_argument(
        "--log", type=str, default="server_log.csv",
        help="Path to the CSV log file (default: server_log.csv)."
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_server(port=args.port,
               max_connections=args.max_connections,
               log_path=args.log)
