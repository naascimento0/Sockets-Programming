import os
import socket
from tqdm import tqdm
import logging
from checksum import calculate_md5
import threading
from auth import authenticate
import queue

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SERVER = socket.gethostbyname(socket.gethostname())
PORT = 4455
ADDR = (SERVER, PORT)
SIZE = 1024  # Increased buffer size for better data transfer
CHUNK_SIZE = 16  # Size for file data chunks
FORMAT = 'utf-8'

# Priority queue for client connections
client_queue = queue.PriorityQueue()

def handle_client(conn, addr):
    """ Handle a single client connection """
    try:
        # Receiving the filename, filesize and checksum from the client
        data = conn.recv(SIZE).decode(FORMAT)
        logging.info(f"SERVER: [+] Received data: {data}")

        if "@" not in data:
            logging.error("[!] Invalid data format received")
            conn.send("ERROR: Invalid data format".encode(FORMAT))
            return
        
        try:
            item = data.split("@")
            filename = item[0]
            filesize = int(item[1])
            original_md5 = item[2]
            logging.info(f"[+] Filename: {filename}, Filesize: {filesize} bytes, Expected MD5: {original_md5}")
        except (IndexError, ValueError) as e:
            logging.error(f"[!] Error parsing filename/filesize/checksum: {e}")
            conn.send("ERROR: Invalid filename or filesize".encode(FORMAT))
            return
        
        conn.send("Filename and filesize received".encode(FORMAT))

        """ Data transfer """
        bar = tqdm(range(filesize), f"Receiving {filename} from {addr[0]}:{addr[1]}", unit="B", unit_scale=True, unit_divisor=CHUNK_SIZE)
        received_bytes = 0
        received_filename = f"server_received_{addr[0]}_{addr[1]}_{filename}" # Unique filename per client

        with open(received_filename, "w", encoding=FORMAT) as f:
            while received_bytes < filesize:
                try:
                    data = conn.recv(CHUNK_SIZE).decode(FORMAT)
                    
                    if not data:
                        logging.warning("[!] No data received, connection might be closed")
                        break

                    f.write(data)
                    received_bytes += len(data)
                    conn.send("Data received.".encode(FORMAT))
                    bar.update(len(data))
                    
                except UnicodeDecodeError as e:
                    logging.error(f"[!] Unicode decode error: {e}")
                    break
                except Exception as e:
                    logging.error(f"[!] Error during data transfer: {e}")
                    break

        bar.close()
        logging.info(f"[+] File transfer completed for {addr[0]}:{addr[1]}. Received {received_bytes}/{filesize} bytes")

        """ Check integrity after data transfer """
        logging.info(f"SERVER: [+] Verifying file integrity for {received_filename}...")
        received_md5 = calculate_md5(received_filename)
        
        if received_md5 == original_md5:
            logging.info(f"✅ [+] FILE INTEGRITY VERIFIED for {addr[0]}:{addr[1]}! Checksums match.")
            conn.send("INTEGRITY_OK".encode(FORMAT))
        else:
            logging.error("❌ [!] FILE INTEGRITY FAILED for {addr[0]}:{addr[1]}! Checksums don't match.")
            logging.error(f"[!] Expected: {original_md5}")
            logging.error(f"[!] Received: {received_md5}")
            conn.send("INTEGRITY_FAILED".encode(FORMAT))

    except Exception as e:
        logging.error(f"[!] Client {addr[0]}:{addr[1]} error: {e}")
    finally:
        conn.close()
        logging.info(f"[+] Connection closed for {addr[0]}:{addr[1]}")

def process_client_queue():
    """ Process clients from the priority queue """
    while True:
        try:
            # Get client from queue (blocks until there is an item)
            priority, conn, addr = client_queue.get()
            logging.info(f"[+] Processing client {addr[0]}:{addr[1]} with priority {priority}")
            handle_client(conn, addr)
            client_queue.task_done()
        except Exception as e:
            logging.error(f"[!] Error processing client queue: {e}")
        
def main():
    """ Creating a TCP server socket """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Reuse address
    server.bind(ADDR)
    server.listen()
    logging.info(f"[+] Server listening on {SERVER}:{PORT}")

    """ Start thread to process client queue """
    queue_thread = threading.Thread(target=process_client_queue, daemon=True)
    queue_thread.start()

    """ Accepting connections from clients """
    try:
        while True:
            conn, addr = server.accept()
            logging.info(f"SERVER: [+] Client connected from {addr[0]}:{addr[1]}")

            # Receive credentials to determine priority
            credentials = conn.recv(SIZE).decode(FORMAT)
            logging.info(f"SERVER: [+] Received credentials: {credentials}")
            
            auth_success, priority = authenticate(credentials)
            if not auth_success:
                logging.error(f"SERVER: [!] Authentication failed for {addr[0]}:{addr[1]}")
                conn.send("AUTH_FAILED".encode(FORMAT))
                conn.close()
                continue
            conn.send("AUTH_OK".encode(FORMAT))
            logging.info(f"SERVER: [+] Authentication successful for {addr[0]}:{addr[1]}, Priority: {priority}")

            # Add client to priority queue
            client_queue.put((priority, conn, addr))
            logging.info(f"[+] Client {addr[0]}:{addr[1]} added to queue. Queue size: {client_queue.qsize()}")
    
    except KeyboardInterrupt:
        logging.info("[+] Server shutting down...")
    finally:
        server.close()
        logging.info("[+] Server closed")

if __name__ == "__main__":
    main()