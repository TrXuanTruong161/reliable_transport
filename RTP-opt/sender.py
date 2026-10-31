
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

    if len(data) != 16 + header.length:
        return None

    payload = data[16:]
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

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        message = sys.stdin.buffer.read()

        chunks = [
            message[i:i + MAX_PAYLOAD]
            for i in range(0, len(message), MAX_PAYLOAD)
        ]

        total_packets = len(chunks)

        # Phase 1: START handshake
        start_packet = make_packet(0, 0)
        sock.settimeout(TIMEOUT)

        while True:
            sock.sendto(start_packet, receiver_address)

            try:
                data, address = sock.recvfrom(2048)

                if address != receiver_address:
                    continue

                if parse_ack(data) == 1:
                    break

            except socket.timeout:
                continue

        # Phase 2: DATA transfer
        packets = {
            seq: make_packet(2, seq, payload)
            for seq, payload in enumerate(chunks, start=1)
        }

        base = 1
        next_seq = 1

        # Tracks individually acknowledged DATA packets
        acked = set()

        # One retransmission timer for the window
        timer = None

        while base <= total_packets:

            # Send new packets within the current window
            while (
                next_seq <= total_packets
                and next_seq < base + window_size
            ):
                sock.sendto(
                    packets[next_seq],
                    receiver_address
                )

                if timer is None:
                    timer = time.monotonic() + TIMEOUT

                next_seq += 1

            # If the timer expires, retransmit only
            # unacknowledged packets
            remaining = timer - time.monotonic()

            if remaining <= 0:
                for seq in range(base, next_seq):
                    if seq not in acked:
                        sock.sendto(
                            packets[seq],
                            receiver_address
                        )

                timer = time.monotonic() + TIMEOUT
                continue

            sock.settimeout(remaining)

            try:
                data, address = sock.recvfrom(2048)

                if address != receiver_address:
                    continue

                ack_num = parse_ack(data)

                if ack_num is None:
                    continue

                # Individual ACK
                if base <= ack_num < next_seq:
                    acked.add(ack_num)

                    # Slide window only over consecutively
                    # acknowledged packets
                    old_base = base

                    while base in acked:
                        acked.remove(base)
                        base += 1

                    if base != old_base:
                        if base < next_seq:
                            timer = time.monotonic() + TIMEOUT
                        else:
                            timer = None

            except socket.timeout:
                # Retransmit only missing DATA packets
                for seq in range(base, next_seq):
                    if seq not in acked:
                        sock.sendto(
                            packets[seq],
                            receiver_address
                        )

                timer = time.monotonic() + TIMEOUT

        # Phase 3: END handshake
        end_seq = total_packets + 1
        end_packet = make_packet(1, end_seq)

        sock.sendto(end_packet, receiver_address)
        end_deadline = time.monotonic() + TIMEOUT

        while True:
            remaining = end_deadline - time.monotonic()

            if remaining <= 0:
                break

            sock.settimeout(remaining)

            try:
                data, address = sock.recvfrom(2048)

                if address != receiver_address:
                    continue

                if parse_ack(data) == end_seq + 1:
                    break

            except socket.timeout:
                break

    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("receiver_ip")
    parser.add_argument("receiver_port", type=int)
    parser.add_argument("window_size", type=int)

    args = parser.parse_args()

    sender(
        args.receiver_ip,
        args.receiver_port,
        args.window_size
    )


if __name__ == "__main__":
    main()
