import os.path, socket, random, threading

UDP_IP = "0.0.0.0"
UDP_PORT = 69 # TFTP Protocol Port (69)

SOCK_TIMEOUT = 5
MAX_TIMEOUT_RETRIES = 5
SESSIONS = dict()
FILE_DIR = os.path.dirname(os.path.realpath(__file__))

# header opcode is 2 bytes
TFTP_OPCODES = {
    1: 'RRQ',
    2: 'WRQ',
    3: 'DATA',
    4: 'ACK',
    5: 'ERROR'
}
TRANSFER_MODES = ['netascii', 'octet', 'mail']
TFTP_ERRORS = {
    0: 'Not Defined',
    1: 'File Not Found',
    2: 'Access Violation',
    3: 'Disk Full or Allocation Exceeded',
    4: 'Illegal TFTP operation',
    5: 'Unknown Transfer TID',
    6: 'File Already Exists',
    7: 'No Such User'
}


def create_data_packet(block, filename, mode):
    data = bytearray()
    # append data opcode (03)
    data.append(0)
    data.append(3)

    # append block number (2 bytes)
    b = f'{block:02}'
    data.append(int(b[0]))
    data.append(int(b[1]))

    # append data (512 bytes max)
    content = read_file(block, filename)
    data += content

    return data


def create_ack_packet(block):
    ack = bytearray()
    # append acknowledgement opcode (04)
    ack.append(0)
    ack.append(4)

    # append block number (2 bytes)
    b = f'{block:02}'
    ack.append(int(b[0]))
    ack.append(int(b[1]))

    return ack


def create_error_packet(error_code):
    err = bytearray()
    # append error opcode (05)
    err.append(0)
    err.append(5)

    # append error code
    ec = f'{error_code:02}'
    err.append(int(ec[0]))
    err.append(int(ec[1]))

    # append error message followed by null terminator
    msg = bytearray(TFTP_ERRORS[error_code].encode('utf-8'))
    err += msg
    err.append(0)

    return err


def send_packet(packet, socket, addr):
    socket.sendto(packet, addr)


def read_file(block, filename):
    with open(filename, 'rb') as f:
        offset = (block - 1) * 512
        f.seek(offset, 0)
        content = f.read(512)
    return content


# Get opcode from TFTP header
def get_opcode(bytes):
    opcode = int.from_bytes(bytes[0:2], byteorder='big')
    if opcode not in TFTP_OPCODES.keys():
        return False
    return TFTP_OPCODES[opcode]


# Return filename and mode from decoded RRQ/WRQ header
def decode_request_header(data):
    header = data[2:].split(b'\x00')
    filename = header[0].decode('utf-8');
    mode = header[1].decode('utf-8').lower()
    return filename, mode


# Find a random port between 1025 and 65535 that is not in use
# by this service
def get_random_port():
    while True:
        port = random.randint(1025, 65536)
        if(port not in SESSIONS.keys()):
            return port


def create_udp_socket(ip=UDP_IP, port=UDP_PORT):
    sock = socket.socket(socket.AF_INET,   # Internet
                        socket.SOCK_DGRAM) # UDP
    sock.bind((ip, port))
    return sock


# Remove session and close socket
def close_connection(sock):
    port = sock.getsockname()[1]
    del SESSIONS[port]
    sock.close()


def listen(sock, filename, mode):
    (ip, port) = sock.getsockname()
    session = SESSIONS[port]

    try:
        while True:
            try:
                sock.settimeout(SOCK_TIMEOUT)
                data, addr = sock.recvfrom(1024) # buffer size is 2014 bytes
                session['consec_timeouts'] = 0
                print(f'thread data: {data}')
                print(f'thread addr: {addr}')

                # Check address (IP, port) matches initial connection address
                if addr != session['addr']:
                    packet = create_error_packet(5)
                    send_packet(packet, socket, addr)
                    break

                opcode = get_opcode(data)
                print(opcode)
                if opcode == 'ACK':
                    block = int.from_bytes(data[2:4], byteorder='big')
                    # Check length of the last DATA packet sent, if the Datagram length is 
                    # less than 516 it is the last packet. Upon receiving the final ACK packet
                    # from the client we can terminate the connection.
                    if(len(session['packet']) < 516 and block == int.from_bytes(session['packet'][2:4], byteorder="big")):
                        break

                    packet = create_data_packet(block + 1, filename, mode)
                    session['packet'] = packet
                    send_packet(packet, sock, addr)
                elif opcode == 'DATA':
                    block = int.from_bytes(data[2:4], byteorder='big')
                    content = data[4:]
                    with open(filename, 'ab+') as f:
                        f.write(content)

                    packet = create_ack_packet(block)
                    session['packet'] = packet
                    send_packet(packet, sock, addr)

                    # Close connection once all data has been received and final 
                    # ACK packet has been sent
                    if len(content) < 512:
                        print('closing connection')
                        break
                else:
                    # Threads only handle incoming packets with ACK/DATA opcodes, send
                    # 'Illegal TFTP Operation' ERROR packet for any other opcode.
                    packet = create_error_packet(4)
                    send_packet(packet, sock, addr)
            except socket.timeout:
                print(session['consec_timeouts'])
                if session['consec_timeouts'] < MAX_TIMEOUT_RETRIES:
                    session['consec_timeouts'] += 1
                    send_packet(session['packet'], sock, session['addr'])
                else:
                    break
        
        close_connection(sock)
        return False
    except Exception as e:
        print(e)
        close_connection(sock) 
        return False # returning from the thread's run() method ends the thread



def main():
    sock = create_udp_socket()
    
    while True:
        data, addr = sock.recvfrom(1024)
        print(f'data: {data}')
        print(f'addr: {addr}')

        opcode = get_opcode(data)
        print(opcode)
        if opcode == 'RRQ' or opcode == 'WRQ':
            filename, mode = decode_request_header(data)
            print(filename)

            if mode not in TRANSFER_MODES or mode == 'mail':
                packet = create_error_packet(0)
                send_packet(packet)
                continue
            print(filename, mode)
            # Check for '/' in filename as a simple check to prevent unwanted
            # file system access, and send 'Access Violation' ERROR packet
            if '/' in filename:
                packet = create_error_packet(2)
                send_packet(packet, sock, addr)
                continue

            if opcode == 'RRQ':
                # Check if file doesn't exist
                if not os.path.isfile(f'{FILE_DIR}/{filename}'):
                    packet = create_error_packet(1)
                    send_packet(packet, sock, addr)
                    continue

                packet = create_data_packet(1, filename, mode)
            else:
                # Create empty file if file doesn't exist, otherwise send ERROR
                if not os.path.isfile(f'{FILE_DIR}/{filename}'):
                    with open(filename, 'w+'):
                        pass
                else:
                    packet = create_error_packet(6)
                    send_packet(packet, sock, addr)
                    continue

                packet = create_ack_packet(0)
            
            port = get_random_port()
            SESSIONS[port] = {
                'addr': addr, 
                'packet': packet,
                'consec_timeouts': 0
            }

            client_socket = create_udp_socket(port=port)
            send_packet(packet, client_socket, addr)
            print(filename)
            threading.Thread(target=listen, args=(client_socket, filename, mode)).start()
        else:
            # This socket only handles incoming packets with RRQ or WRQ opcodes, send
            # 'Illegal TFTP Operation' ERROR packet for any other opcode.
            packet = create_error_packet(4)
            send_packet(packet, sock, addr)


if __name__ == '__main__':
    
    main()
    