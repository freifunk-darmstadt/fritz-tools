import os.path, random, sys
from socket import socket, AF_INET, AF_INET6, SOCK_DGRAM, timeout
from pathlib import Path
from contextlib import contextmanager
from typing import Tuple, Generator, Literal

UDP_IP = "0.0.0.0"
UDP_PORT = 69  # TFTP Protocol Port (69)

SOCK_TIMEOUT = 5
MAX_TIMEOUT_RETRIES = 5
SESSIONS = dict()
FILE_DIR = Path(__file__)

# header opcode is 2 bytes
TFTP_OPCODES = {1: "RRQ", 2: "WRQ", 3: "DATA", 4: "ACK", 5: "ERROR"}

TRANSFER_MODES = ["netascii", "octet", "mail"]
TRANSFER_MODES_T = Literal["netascii", "octet", "mail"]

TFTP_ERRORS = {
    0: "Not Defined",
    1: "File Not Found",
    2: "Access Violation",
    3: "Disk Full or Allocation Exceeded",
    4: "Illegal TFTP operation",
    5: "Unknown Transfer TID",
    6: "File Already Exists",
    7: "No Such User",
}
TFTP_ERRORS_T = Literal[0, 1, 2, 3, 4, 5, 6, 7]


def create_data_packet(block, file: Path, mode: TRANSFER_MODES_T) -> bytes:
    data = bytearray()
    # append data opcode (03)
    data.append(0)
    data.append(3)

    # append block number (2 bytes)
    b = f"{block:02}"
    data.append(int(b[0]))
    data.append(int(b[1]))

    # append data (512 bytes max)
    content = read_file(block, file)
    data += content

    return bytes(data)


def create_ack_packet(block) -> bytes:
    ack = bytearray()
    # append acknowledgement opcode (04)
    ack.append(0)
    ack.append(4)

    # append block number (2 bytes)
    b = f"{block:02}"
    ack.append(int(b[0]))
    ack.append(int(b[1]))

    return bytes(ack)


def create_error_packet(error_code: TFTP_ERRORS_T) -> bytes:
    err = bytearray()
    # append error opcode (05)
    err.append(0)
    err.append(5)

    # append error code
    ec = f"{error_code:02}"
    err.append(int(ec[0]))
    err.append(int(ec[1]))

    # append error message followed by null terminator
    msg = bytearray(TFTP_ERRORS[error_code].encode("utf-8"))
    err += msg
    err.append(0)

    return bytes(err)


def read_file(block: int, file: Path) -> str:
    with file.open("rb") as f:
        offset = (block - 1) * 512
        f.seek(offset, 0)
        content = f.read(512)
    return content


# Get opcode from TFTP header
def get_opcode(bytes):
    opcode = int.from_bytes(bytes[0:2], byteorder="big")
    if opcode not in TFTP_OPCODES.keys():
        return False
    return TFTP_OPCODES[opcode]


# Return filename and mode from decoded RRQ/WRQ header
def decode_request_header(data) -> Tuple[Path, TRANSFER_MODES_T]:
    header = data[2:].split(b"\x00")
    file = Path(header[0].decode("utf-8"))
    mode = header[1].decode("utf-8").lower()
    return file, mode


# Find a random port between 1025 and 65535 that is not in use
# by this service
def get_random_port() -> int:
    while True:
        port = random.randint(1025, 65536)
        if port not in SESSIONS.keys():
            return port


@contextmanager
def create_udp_socket(ip=UDP_IP, port=UDP_PORT) -> Generator[socket, None, None]:
    sock = socket(AF_INET, SOCK_DGRAM)  # Internet  # UDP
    sock.bind((ip, port))
    try:
        yield sock
    finally:
        _, port = sock.getsockname()
        if port in SESSIONS:
            del SESSIONS[port]
        sock.close()


def serve(port: int, file: Path, mode: TRANSFER_MODES_T) -> Tuple[bool, str]:
    session = SESSIONS[port]

    with create_udp_socket(port=port) as sock:
        packet = create_data_packet(1, file, mode)
        sock.sendto(packet, session["addr"])
        
        SESSIONS[port]["packet"] = packet
        
        while True:
            try:
                sock.settimeout(SOCK_TIMEOUT)
                data, addr = sock.recvfrom(1024)  # buffer size is 2014 bytes
                session["consec_timeouts"] = 0

                # Check address (IP, port) matches initial connection address
                if addr != session["addr"]:
                    sock.sendto(create_error_packet(5), addr)

                opcode = get_opcode(data)
                if opcode == "ACK":
                    len_block_ack = int.from_bytes(data[2:4], byteorder="big")
                    len_last_sent = int.from_bytes(
                        session["packet"][2:4], byteorder="big"
                    )
                    # Check length of the last DATA packet sent, if the Datagram length is
                    # less than 516 it is the last packet. Upon receiving the final ACK packet
                    # from the client we can terminate the connection.
                    if len(session["packet"]) < 516 and len_block_ack == len_last_sent:
                        return True, addr

                    packet = create_data_packet(block + 1, file, mode)
                    sock.sendto(packet, addr)
                    session["packet"] = packet
                else:
                    # Threads only handle incoming packets with ACK opcodes, send
                    # 'Illegal TFTP Operation' ERROR packet for any other opcode.
                    sock.sendto(create_error_packet(4), addr)
            except timeout:
                if session["consec_timeouts"] < MAX_TIMEOUT_RETRIES:
                    session["consec_timeouts"] += 1
                    sock.sendto(session["packet"], session["addr"])
                else:
                    return False, addr


def serve_file(file: Path) -> Generator[Tuple[bool, str], None, None]:
    file = Path(file)
    sessions = {}

    with create_udp_socket(port=69) as server_sock:
        print(f"TFTP Server started listening on Port 69, serving {file}")

        # yield file transfers until
        while True:
            data, addr = server_sock.recvfrom(1024)
            opcode = get_opcode(data)
            # Only serving read operations
            if opcode != "RRQ":
                server_sock.sendto(create_error_packet(4), addr)
                continue
            rfile, mode = decode_request_header(data)
            # Mail is deprecated
            if not mode in TRANSFER_MODES or mode == "mail":
                server_sock.sendto(create_error_packet(0), addr)
                continue
            # Only serving a specific file
            if rfile != Path(file.name):
                server_sock.sendto(create_error_packet(1), addr)
                continue

            port = get_random_port()
            SESSIONS[port] = {"addr": addr, "packet": None, "consec_timeouts": 0}
            yield serve(port, file, mode)


if __name__ == "__main__":
    for success, host in serve_file(sys.argv[1]):
        if success:
            print(f"Successfully served file {sys.argv[1]} to Host {host}")
            try:
                input("Press any key to serve to another Host, CTRL-c or CTRL-d to stop TFTP server.")
            except (KeyboardInterrupt, EOFError) as interrupt:
                break
        else:
            print(f"Timeout serving file to Host {host}")
