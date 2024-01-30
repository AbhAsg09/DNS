# DNS Server Project

## Overview

This project is a simple DNS server implemented in Python that provides both authoritative and recursive DNS resolution. It includes features such as caching, logging, and encryption for enhanced security.

## Features

- **Authoritative DNS Server:** Supports loading and serving DNS zone files.
- **Recursive DNS Resolution:** Resolves external DNS queries recursively.
- **Caching:** Implements a caching mechanism to store DNS responses and reduce latency.
- **Logging:** Logs DNS queries and responses in a secure and encrypted manner.
- **Encryption:** Utilizes Fernet symmetric encryption for log file data.
- **Redis Integration:** Incorporates Redis for caching and storing DNS data.

## Technologies Used

- **Python:** The primary programming language used for the implementation.
- **Socket Programming:** Handles UDP socket communication for DNS queries and responses.
- **JSON:** Zone files are loaded and stored in JSON format.
- **Redis:** Integrates Redis for caching DNS responses and data storage.
- **Fernet Encryption:** Implements Fernet encryption for secure log file storage.

## Project Structure

- `main.py`: The main DNS server implementation.
- `zones/`: Directory containing DNS zone files in JSON format.
- `logs/`: Directory for storing encrypted DNS query and response logs.
- `read_logs.py/`: A simple python script that can be used to read the log file.

## Install and Start Redis

- To install Redis run the command `sudo apt-get install redis`
- To start the redis server run the command `redis-server`
- To verify the server is running run the command `redis-cli ping`



