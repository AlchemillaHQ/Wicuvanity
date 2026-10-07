import argparse
import base64
import os
from pathlib import Path
import signal
import subprocess

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


parser = argparse.ArgumentParser(description="Check a built wicuvanity binary against OpenSSL")
parser.add_argument("binary", type=Path)
parser.add_argument("--seconds", type=float, default=2, help="search duration per case")
args = parser.parse_args()
binary = str(args.binary.resolve())

invalid_searches = [
    ["--in", "10", "="],
    ["--in", "43", "="],
    ["--in", "44", "=="],
    ["--in", "44", "=A"],
    ["--in", "44", "B="],
    ["--case-sensitive", "--in", "44", "C="],
    ["--case-sensitive", "--in", "42", "A" * 41 + "I"],
    ["--in", "43", "A" * 42 + "B"],
    ["--in", "44", "A" * 44],
]
for search in invalid_searches:
    result = subprocess.run(
        [binary, *search],
        capture_output=True,
        text=True,
        timeout=10,
        env={**os.environ, "CUDA_VISIBLE_DEVICES": ""},
    )
    assert result.returncode == 1, (search, result.returncode, result.stderr)
    assert "needle cannot match" in result.stderr, (search, result.stderr)
print(f"Rejected {len(invalid_searches)} impossible searches before GPU initialization")

searches = [
    (44, "=", False, 1),
    (44, "C=", False, 64),
    (44, "AA=", True, 64),
    (43, "a", True, 64),
    (1, "A", True, 64),
    (1, "A", False, 64),
]
for window, needle, sensitive, block in searches:
    command = [binary, "--gridsize", "1", "--blocksize", str(block), "--in", str(window), needle]
    if sensitive:
        command.append("--case-sensitive")
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        stdout, stderr = process.communicate(timeout=args.seconds)
    except subprocess.TimeoutExpired:
        process.send_signal(signal.SIGTERM)
        try:
            stdout, stderr = process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise
    assert process.returncode == 0, (command, process.returncode, stderr)
    lines = stdout.splitlines()
    assert lines, (command, stderr)
    private_keys = []
    for line in lines:
        private, public = line.removeprefix("private: ").split(" | public: ")
        key, pub = base64.b64decode(private), base64.b64decode(public)
        assert key[0] & 7 == 0 and key[31] & 0xC0 == 0x40, "private key is not clamped"
        expected = X25519PrivateKey.from_private_bytes(key).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        assert pub == expected, "GPU public key differs from OpenSSL"
        candidate = public[:window]
        if sensitive:
            assert needle in candidate, (needle, public)
        else:
            assert needle.lower() in candidate.lower(), (needle, public)
        private_keys.append(int.from_bytes(key, "little"))

    ordered = sorted(private_keys)
    assert all(b - a > 248 for a, b in zip(ordered, ordered[1:])), "duplicate or related private keys"
    if block == 1:
        assert len(lines) >= 64 and len(lines) % 32 == 0, "expected multiple complete batches"
    print(f"Verified {len(lines)} keypairs: --in {window} {needle!r}, case-sensitive={sensitive}")
