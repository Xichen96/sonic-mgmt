import argparse
import json
import socket
import struct
import time


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    value = sum(struct.unpack("!{}H".format(len(data) // 2), data))
    while value >> 16:
        value = (value & 0xffff) + (value >> 16)
    return (~value) & 0xffff


def icmp_bounds(frame):
    if len(frame) < 14 + 20 + 8 + 24 or frame[12:14] != b"\x08\x00":
        return None
    if frame[14] != 0x45 or frame[23] != 1:
        return None
    end = 14 + struct.unpack_from("!H", frame, 16)[0]
    if end > len(frame) or end < 14 + 20 + 8 + 24:
        return None
    return 34, end


def make_probe(capture, source_macs, nonce):
    if isinstance(source_macs, str):
        source_macs = [source_macs]
    sources = {bytes.fromhex(mac.replace(":", "")) for mac in source_macs}
    if not sources or any(len(source) != 6 for source in sources) or not 0 <= nonce < (1 << 64):
        raise ValueError("Invalid source MAC or diagnostic nonce")
    with open(capture, "rb") as stream:
        header = stream.read(24)
        if len(header) != 24:
            raise ValueError("Incomplete baseline PCAP header")
        orders = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
                  b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}
        if header[:4] not in orders:
            raise ValueError("Unsupported baseline capture format")
        order = orders[header[:4]]
        if struct.unpack_from(order + "I", header, 20)[0] != 1:
            raise ValueError("Baseline capture is not Ethernet")
        while True:
            record = stream.read(16)
            if len(record) != 16:
                break
            length = struct.unpack_from(order + "I", record, 8)[0]
            frame = stream.read(length)
            bounds = icmp_bounds(frame)
            if bounds is None or frame[6:12] not in sources:
                continue
            start, end = bounds
            if frame[start] != 8 or struct.unpack_from("!I", frame, start + 12)[0] != 0:
                continue
            if frame[start + 16:start + 24] == b"\x00" * 8:
                continue
            if checksum(frame[14:34]) != 0 or checksum(frame[start:end]) != 0:
                raise ValueError("Baseline heartbeat checksum is invalid")
            probe = bytearray(frame[:end])
            # Both pinned ToR parsers reject zero GUID before Self/Peer bookkeeping.
            probe[start + 16:start + 24] = b"\x00" * 8
            struct.pack_into("!Q", probe, start + 24, nonce)
            struct.pack_into("!H", probe, start + 6, nonce & 0xffff)
            struct.pack_into("!H", probe, start + 2, 0)
            struct.pack_into("!H", probe, start + 2, checksum(bytes(probe[start:end])))
            return bytes(probe)
    raise ValueError("No complete version-zero baseline heartbeat from an upper MAC")


def matches_reply(frame, request):
    bounds = icmp_bounds(frame)
    if bounds is None:
        return False
    start, end = bounds
    request_start, request_end = icmp_bounds(request)
    return (
        frame[start] == 0 and frame[start + 1] == 0
        and frame[:6] == request[6:12] and frame[6:12] == request[:6]
        and frame[26:30] == request[30:34] and frame[30:34] == request[26:30]
        and frame[start + 4:start + 8] == request[request_start + 4:request_start + 8]
        and frame[start + 8:end] == request[request_start + 8:request_end]
        and checksum(frame[14:34]) == 0 and checksum(frame[start:end]) == 0
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", required=True)
    parser.add_argument("--source-mac", required=True, action="append")
    parser.add_argument("--interface", required=True)
    parser.add_argument("--nonce", required=True, type=int)
    parser.add_argument("--timeout", type=float, default=15)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    request = make_probe(args.capture, args.source_mac, args.nonce)
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as channel:
        channel.bind((args.interface, 0))
        sent = time.time()
        if channel.send(request) != len(request):
            raise RuntimeError("Diagnostic frame was not completely sent")
        deadline = time.monotonic() + args.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("No matching ignored-health diagnostic echo reply")
            channel.settimeout(remaining)
            frame = channel.recv(65535)
            if matches_reply(frame, request):
                print(json.dumps({"reply_received": True, "nonce": args.nonce,
                                  "tx_epoch": sent, "rx_epoch": time.time(),
                                  "request_hex": request.hex(), "reply_hex": frame.hex()}))
                return


if __name__ == "__main__":
    main()
