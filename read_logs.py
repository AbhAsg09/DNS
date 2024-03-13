from cryptography.fernet import Fernet

# Load the encryption key from the file
with open('encryption_key.txt', 'rb') as key_file:
    encryption_key = key_file.read()

cipher_suite = Fernet(encryption_key)

# Specify the path to the encrypted log file
encrypted_log_file_path = 'logs/dns_server.log'

# Function to decrypt and print log entries
def decrypt_and_print_logs():
    with open(encrypted_log_file_path, 'rb') as log_file:
        for encrypted_entry in log_file:
            try:
                decrypted_entry = cipher_suite.decrypt(encrypted_entry).decode()
                print(decrypted_entry)
            except Exception as e:
                print(f"Error decrypting log entry: {e}")

# Run the decryption and printing function
decrypt_and_print_logs()
