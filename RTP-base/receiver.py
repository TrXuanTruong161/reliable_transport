
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

    if header.length < 0:
        return None

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

            # Drop corrupted or malformed packets
            if parsed is None:
                continue

            packet_type, seq_num, payload = parsed

            # START handshake
            if packet_type == START:
                if sender_address is None:
                    sender_address = address
                    expected_seq = 1
                    buffer.clear()

                    sock.sendto(
                        make_ack(expected_seq),
                        sender_address
                    )

                # Ignore START during an existing connection
                continue

            # Ignore packets from unknown senders
            if address != sender_address:
                continue

            # DATA packet
            if packet_type == DATA:

                # Packet is already acknowledged
                if seq_num < expected_seq:
                    sock.sendto(
                        make_ack(expected_seq),
                        sender_address
                    )
                    continue

                # Packet is outside the receiving window
                if seq_num >= expected_seq + window_size:
                    continue

                # Store valid packet within the window
                if seq_num not in buffer:
                    buffer[seq_num] = payload

                # Deliver consecutive packets in order
                while expected_seq in buffer:
                    data = buffer.pop(expected_seq)

                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()

                    expected_seq += 1

                # Send cumulative ACK
                sock.sendto(
                    make_ack(expected_seq),
                    sender_address
                )

            # END handshake
            elif packet_type == END:

                if seq_num == expected_seq:
                    expected_seq += 1

                    sock.sendto(
                        make_ack(expected_seq),
                        sender_address
                    )

                    break

                # Still waiting for missing DATA
                sock.sendto(
                    make_ack(expected_seq),
                    sender_address
                )

    finally:
        sock.close()


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

    receiver(
        args.receiver_ip,
        args.receiver_port,
        args.window_size
    )


if __name__ == "__main__":
    main()
