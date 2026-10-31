
import argparse
import socket
import sys
import time

from utils import PacketHeader, compute_checksum


MAX_PAYLOAD = 1456
TIMEOUT = 0.5


def make_packet(packet_type, seq_num, payload=b""):
    header = PacketHeader(
        type=packet_type,
        seq_num=seq_num,
        length=len(payload),
        checksum=0
    )

    header.checksum = compute_checksum(header / payload)

    return bytes(header / payload)


def parse_ack(data):
    if len(data) < 16:
        return None

    header = PacketHeader(data[:16])

    if header.type != 3:
        return None

    if len(data) < 16 + header.length:
        return None

    payload = data[16:16 + header.length]

    received_checksum = header.checksum
    header.checksum = 0

    if received_checksum != compute_checksum(header / payload):
        return None

    return header.seq_num


def sender(receiver_ip, receiver_port, window_size):
    if window_size <= 0:
        raise ValueError("Window size must be greater than 0")

    receiver_address = (
        socket.gethostbyname(receiver_ip),
        receiver_port
    )

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        # Read all input data
        message = sys.stdin.buffer.read()

        # Split message into payloads
        chunks = [
            message[i:i + MAX_PAYLOAD]
            for i in range(0, len(message), MAX_PAYLOAD)
        ]

        # START handshake
        start_packet = make_packet(0, 0)

        s.settimeout(TIMEOUT)

        while True:
            s.sendto(start_packet, receiver_address)

            try:
                data, address = s.recvfrom(2048)

                if address != receiver_address:
                    continue

                ack_num = parse_ack(data)

                if ack_num == 1:
                    break

            except socket.timeout:
                continue

        # Prepare DATA packets
        packets = {
            seq: make_packet(2, seq, payload)
            for seq, payload in enumerate(chunks, start=1)
        }

        total_packets = len(chunks)

        # Sliding window
        base = 1
        next_seq = 1
        timer = None

        while base <= total_packets:

            # Send packets while the window has space
            while (
                next_seq <= total_packets
                and next_seq < base + window_size
            ):
                s.sendto(packets[next_seq], receiver_address)

                if timer is None:
                    timer = time.monotonic() + TIMEOUT

                next_seq += 1

            remaining = timer - time.monotonic()

            # Retransmit outstanding packets on timeout
            if remaining <= 0:
                for seq in range(base, next_seq):
                    s.sendto(packets[seq], receiver_address)

                timer = time.monotonic() + TIMEOUT
                continue

            s.settimeout(remaining)

            try:
                data, address = s.recvfrom(2048)

                if address != receiver_address:
                    continue

                ack_num = parse_ack(data)

                if ack_num is None:
                    continue

                # Cumulative ACK
                if base < ack_num <= next_seq:
                    base = ack_num

                    if base < next_seq:
                        timer = time.monotonic() + TIMEOUT
                    else:
                        timer = None

            except socket.timeout:
                for seq in range(base, next_seq):
                    s.sendto(packets[seq], receiver_address)

                timer = time.monotonic() + TIMEOUT

        # END handshake
        # Exit after receiving END ACK or after 500 ms
        end_seq = total_packets + 1
        end_packet = make_packet(1, end_seq)

        end_deadline = time.monotonic() + TIMEOUT

        s.sendto(end_packet, receiver_address)

        while True:
            remaining = end_deadline - time.monotonic()

            if remaining <= 0:
                break

            s.settimeout(remaining)

            try:
                data, address = s.recvfrom(2048)

                if address != receiver_address:
                    continue

                ack_num = parse_ack(data)

                if ack_num == end_seq + 1:
                    break

            except socket.timeout:
                break

    finally:
        s.close()


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "receiver_ip",
        help="The IP address of the host that receiver is running on"
    )

    parser.add_argument(
        "receiver_port",
        type=int,
        help="The port number on which receiver is listening"
    )

    parser.add_argument(
        "window_size",
        type=int,
        help="Maximum number of outstanding packets"
    )

    args = parser.parse_args()

    sender(
        args.receiver_ip,
        args.receiver_port,
        args.window_size
    )


if __name__ == "__main__":
    main()
