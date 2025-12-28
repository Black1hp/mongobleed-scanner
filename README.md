
# MongoBleed (CVE-2025-14847)

MongoBleed is a high-performance PoC scanner for CVE-2025-14847, a pre-authentication heap memory disclosure vulnerability in the MongoDB C++ Driver.
The tool is designed for rapid identification of vulnerable instances across large network ranges.

## Technical Analysis

The vulnerability stems from an out-of-bounds (OOB) read in the MongoDB wire protocol’s handling of `OP_COMPRESSED` messages.

When a server receives an `OP_COMPRESSED` packet, it relies on the attacker-supplied `uncompressedSize` field to allocate a buffer for decompression. If the actual decompressed data is significantly smaller than the claimed `uncompressedSize`, the driver fails to truncate or clear the buffer. As a result, the server returns the entire allocated memory block, which may contain uninitialized heap data, potentially exposing sensitive information such as session tokens, internal pointers, or fragments of other database queries.

## Features

* Asynchronous I/O using Python `asyncio` for high-concurrency scanning
* Precise detection by validating response length against the requested leak size
* Minimal false positives through verified protocol-level interaction
* Automatic logging of vulnerable targets to `vulnerable_targets.txt`

## Installation

```bash
git clone https://github.com/Black1hp/mongobleed-scanner/
cd mongobleed-scanner
```

No external dependencies required (Python Standard Library only).

## Usage

Basic usage:

```bash
python3 mongobleed.py -i targets.txt
```

Advanced configuration:

```bash
python3 mongobleed.py -i targets.txt -c 100 -t 5
```

### Options

* `-i` : Input file containing targets (IP, domain, or IP:port)
* `-c` : Concurrency level (default: 50)
* `-t` : Connection timeout in seconds (default: 5)

## Detection Logic

The scanner identifies vulnerability by exploiting a size mismatch during the BSON decompression phase:

1. The scanner sends a crafted `OP_COMPRESSED` packet containing a small zlib-compressed payload for example 16-30 bytes .
2. The `uncompressedSize` field in the packet header is intentionally set to a much larger value (e.g., 64KB).
3. A **VULNERABLE** state is confirmed if the MongoDB server responds with a `MessageLength` that aligns with the requested large buffer size rather than the actual decompressed payload size.
4. The server trustfully uses the attacker-provided `uncompressedSize` to define the response length. Since it fails to update this length with the actual bytes written during decompression, it blindly streams the entire allocated heap buffer—including uninitialized memory—back to the client.
5. The scanner validates the response by reading the extra bytes from the stream, which represent uninitialized fragments of the server's heap memory.

## Proof of Concept
<div align="center">
  <video src="https://github.com/user-attachments/assets/450e8f2c-3ecc-4638-a534-6874eedc1413" width="100%" controls>
    Your browser does not support the video tag.
  </video>
</div>

> **Note:** The video above demonstrates the scanner identifying multiple vulnerable instances and capturing heap fragments in real-time.

## Author

**Black1hp**
Security Researcher | Bug Hunter | Red Teamer

* GitHub: [https://github.com/black1hp](https://github.com/black1hp)
* X (Twitter): [https://x.com/black1hp](https://x.com/black1hp)
* Medium: [https://medium.com/@black1hp](https://medium.com/@black1hp)
* LinkedIn: [https://www.linkedin.com/in/black1hp/](https://www.linkedin.com/in/black1hp/)

## Disclaimer

This tool is intended for authorized security testing and research purposes only.
The author is not responsible for any unauthorized use or damage resulting from this tool.
