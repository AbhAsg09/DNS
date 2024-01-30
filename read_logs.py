import csv
from cryptography.fernet import Fernet

# Read encryption key from file
with open('encryption_key.txt', 'rb') as key_file:
    encryption_key = key_file.read()

cipher_suite = Fernet(encryption_key)

# Encrypted log file path
encrypted_log_file_path = 'logs/dns_server.log'


def decrypt_and_read_log(encrypted_data):
    decrypted_data = cipher_suite.decrypt(encrypted_data.encode())
    return decrypted_data.decode()


# Read encrypted log file
with open(encrypted_log_file_path, 'r', newline='') as encrypted_log_file:
    csv_reader = csv.reader(encrypted_log_file)
    for row in csv_reader:
        timestamp, client_ip, query_domain, encrypted_response = row
        decrypted_response = decrypt_and_read_log(encrypted_response)

        # Process the decrypted log data as needed
        print(
            f'Timestamp: {timestamp}, Client IP: {client_ip}, Query Domain: {query_domain}, Decrypted Response: {decrypted_response}')
