
import argparse
import socket
import sys

from utils import PacketHeader, compute_checksum


HEADER_SIZE = 16

START = 0
END = 1
DATA = 2
ACK = 3


def make_ack(seq_num):
    header = PacketHeader(
        type=ACK,
        seq_num=seq_num,
        length=0,
        checksum=0
    )
    header.checksum = compute_checksum(header / b"")
    return bytes(header / b"")


def parse_packet(packet):
    if len(packet) < HEADER_SIZE:
        return None

    header = PacketHeader(packet[:HEADER_SIZE])

    if len(packet) != HEADER_SIZE + header.length:
        return None

    payload = packet[HEADER_SIZE:]
    received_checksum = header.checksum
    header.checksum = 0

    if received_checksum != compute_checksum(header / payload):
        return None

    return header.type, header.seq_num, payload


def receiver(receiver_ip, receiver_port, window_size):
    if window_size <= 0:
        raise ValueError("Window size must be greater than 0")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((receiver_ip, receiver_port))

    sender_address = None
    expected_seq = 0
    buffer = {}

    try:
        while True:
            packet, address = sock.recvfrom(2048)
            parsed = parse_packet(packet)

            if parsed is None:
                continue

            packet_type, seq_num, payload = parsed

            # START handshake: ACK 1
            if packet_type == START:
                if sender_address is None:
                    sender_address = address
                    expected_seq = 1
                    buffer.clear()
                    sock.sendto(make_ack(1), address)
                continue

            if address != sender_address:
                continue

            if packet_type == DATA:
                # Previously received packet
                if seq_num < expected_seq:
                    sock.sendto(make_ack(seq_num), address)
                    continue

                # Outside receiver window
                if seq_num >= expected_seq + window_size:
                    continue

                # Store valid data packet
                if seq_num not in buffer:
                    buffer[seq_num] = payload

                # Individual ACK: acknowledge this packet
                sock.sendto(make_ack(seq_num), address)

                # Deliver consecutive packets in order
                while expected_seq in buffer:
                    data = buffer.pop(expected_seq)
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                    expected_seq += 1

            elif packet_type == END:
                if seq_num == expected_seq:
                    sock.sendto(make_ack(seq_num + 1), address)
                    break

    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("receiver_ip")
    parser.add_argument("receiver_port", type=int)
    parser.add_argument("window_size", type=int)
    args = parser.parse_args()

    receiver(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()
