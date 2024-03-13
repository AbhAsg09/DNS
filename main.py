import csv
import socket
import json
import redis
import glob
import time
from cryptography.fernet import Fernet
import os
import logging
import threading
import yaml

# Function to load configurations from YAML file
def load_config(filename='config.yaml'):
    with open(filename, 'r') as config_file:
        config = yaml.safe_load(config_file)
    return config

# Load configurations
config = load_config()

# IP and port configurations
ip = config['dns_server']['ip']
port = config['dns_server']['port']

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))
except socket.error as e:
    logging.error(f"Socket creation or binding failed: {e}")
    exit()


# Redis configurations
redis_host = config['redis']['host']
redis_port = config['redis']['port']
redis_db = config['redis']['db']
redis_password = config['redis']['password']

# Connect to the Redis server
try:
    # Connect to the Redis server
    redis_client = redis.StrictRedis(
        host=redis_host,
        port=redis_port,
        db=redis_db,
        password=redis_password
    )
except redis.RedisError as e:
    logging.error(f"Failed to connect to Redis server: {e}")
    exit()



# Generating a Fernet key
try:
    encryption_key = Fernet.generate_key()

    with open('encryption_key.txt', 'wb') as key_file:
        key_file.write(encryption_key)

    # Load the key from the file
    with open('encryption_key.txt', 'rb') as key_file:
        encryption_key = key_file.read()

    cipher_suite = Fernet(encryption_key)
except Exception as e:
    logging.error(f"Encryption key generation or loading failed: {e}")
    exit()

# Function to load Zonefiles
def load_zone():
    jsonzone = {}
    zonefile = glob.glob('zones/*.zone')

    for zone in zonefile:
        with open(zone) as zonedata:
            data = json.load(zonedata)
            zonename = data["$origin"]
            jsonzone[zonename] = data
    return jsonzone

zonedata = load_zone()

# Function to create logs directory if it doesn't exist
def create_logs_directory():
    logs_directory = 'logs'
    if not os.path.exists(logs_directory):
        os.makedirs(logs_directory)


# Function to log DNS queries and responses
def log_dns_query(logger, client_ip, query_domain, response):
    try:
        # Combine timestamp, client IP, query domain, and response
        log_entry = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {client_ip} {query_domain} {response}"

        # Encrypt the combined log entry
        encrypted_data = cipher_suite.encrypt(log_entry.encode())

        # Log the encrypted data
        logger.info(f"Client IP: {client_ip}, Query Domain: {query_domain[0]}, Encrypted Response: {encrypted_data.decode()}")

        # Write the encrypted data to the log file
        log_file_path = config['dns_server'].get('log_file', 'logs/dns_server.log')
        with open(log_file_path, 'ab') as log_file:
            log_file.write(encrypted_data + b'\n')

    except Exception as e:
        logger.error(f"Error while logging DNS query: {e}")

# Function to resolve recursive DNS queries
def resolve_recursive(query_domain):
    # Check if the query is already in the Redis cache
    cached_response = redis_client.get(query_domain)

    if cached_response:
        cached_response = json.loads(cached_response.decode('utf-8'))
        timestamp = cached_response['timestamp']
        ttl = cached_response['ttl']

        # Check if the cached response is still valid
        if time.time() < timestamp + ttl:
            return cached_response['records']
    try:
        ip_address = socket.gethostbyname(query_domain)


        ttl = 3600

        redis_client.setex(query_domain, int(ttl), json.dumps({
            'records': [{'ttl': ttl, 'value': ip_address}],
            'timestamp': time.time(),
            'ttl': ttl
        }))

        return [{'ttl': ttl, 'value': ip_address}]
    except socket.gaierror:
        return []

        return [{'ttl': ttl, 'value': ip_address}]
    except socket.gaierror:
        return []

#Creating the flags
def getFlags(flags):

    byte1 = bytes(flags[:1])
    byte2 = bytes(flags[1:2])

    QR = '1'
    OPCODE = ''
    for bit in range(1, 5):
        OPCODE += str(ord(byte1)&(1<<bit))
    AA = '1'
    TC = '0'
    RD = '0'
    RA = '0'
    Z = '000'
    RCODE = '0000'

    return int(QR + OPCODE + AA + TC + RD, 2).to_bytes(1, byteorder='big') + int(RA + Z + RCODE, 2).to_bytes(1, byteorder='big')

# Getting the domain name from query
def getquestiondomain(data):

    state = 0
    expectedlength = 0
    domainstring = ''
    domainparts = []
    x = 0
    y = 0
    for byte in data:
        if state == 1:
            if byte != 0:
                domainstring += chr(byte)
            x += 1
            if x == expectedlength:
                domainparts.append(domainstring)
                domainstring = ''
                state = 0
                x = 0
            if byte == 0:
                domainparts.append(domainstring)
                break
        else:
            state = 1
            expectedlength = byte
        y += 1

    questiontype = data[y:y+2]
    return (domainparts, questiontype)

def getzone(domain):
    global zonedata
    zone_name = '.'.join(domain)
    return zonedata.get(zone_name, {})


def getrecs(data):
    domain, questiontype = getquestiondomain(data)

    qt = ''
    if questiontype == b'\x00\x01':
        qt = 'a'

    zone = getzone(domain)

    # Check if the domain is present in the zone files
    if zone:
        return (zone.get(qt, []), qt, domain)
    else:
        # Perform recursive resolution for external domains
        records = resolve_recursive('.'.join(domain))
        return (records, qt, domain)


def buildquestion(domainname, rectype):
    qbytes = b''

    for part in domainname:
        length = len(part)
        qbytes += bytes([length])

        for char in part:
            qbytes += ord(char).to_bytes(1, byteorder='big')

    if rectype == 'a':
        qbytes += (1).to_bytes(2, byteorder='big')

    qbytes += (1).to_bytes(2, byteorder='big')

    return qbytes

def rectobytes(domainname, rectype, recttl, recval):

    rbytes = b'\xc0\x0c'

    if rectype == 'a':
        rbytes = rbytes + bytes([0]) + bytes([1])

    rbytes = rbytes + bytes([0]) + bytes([1])

    rbytes += int(recttl).to_bytes(4, byteorder='big')

    if rectype == 'a':
        rbytes = rbytes + bytes([0]) + bytes([4])

        for part in recval.split('.'):
            rbytes += bytes([int(part)])
    return rbytes




def build_response(data):
    TransactionID = data[:2]
    Flags = getFlags(data[2:4])
    QDCOUNT = b'\x00\x01'
    ANCOUNT = len(getrecs(data[12:])[0]).to_bytes(2, byteorder='big')
    NSCOUNT = (0).to_bytes(2, byteorder='big')
    ARCOUNT = (0).to_bytes(2, byteorder='big')

    dns_header = TransactionID + Flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT
    dns_body = b''

    records, rectype, domain_name = getrecs(data[12:])
    dns_question = buildquestion(domain_name, rectype)

    for record in records:
        dns_body += rectobytes(domain_name, rectype, record.get("ttl", 0), record.get("value", ''))

    return dns_header + dns_question + dns_body


def get_recs_recursive(data):
    domain, question_type = getquestiondomain(data)
    qt = ''
    if question_type == b'\x00\x01':
        qt = 'A'

    records = resolve_recursive('.'.join(domain))
    return records, qt, domain

# Create logs directory and log file if they don't exist
create_logs_directory()

# Main loop with added error handling
# Function to handle DNS queries
def handle_dns_query(data, addr):
    try:
        # Log client IP and query domain
        print(addr)
        client_ip = addr[0]


        # Build DNS response
        r = build_response(data)

        # Send DNS response
        sock.sendto(r, addr)

        # Log the query and response
        records, _, domain_name = getrecs(data[12:])
        query_domain = '.'.join(domain_name[:-1])
        log_dns_query(logging.getLogger(__name__), client_ip, query_domain, json.dumps(records))

    except socket.error as e:
        logging.error(f"Socket error while processing request: {e}")
    except Exception as e:
        logging.error(f"Unexpected error occurred: {e}")

# Main loop with multithreading
while True:
    data, addr = sock.recvfrom(512)

    # Create a new thread for each DNS query
    threading.Thread(target=handle_dns_query, args=(data, addr)).start()