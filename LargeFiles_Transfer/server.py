import os
import socket
from tqdm import tqdm
import logging
from checksum import calculate_md5
import threading
from auth import authenticate
import queue
from concurrent.futures import ThreadPoolExecutor
import signal
import sys

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SERVER = socket.gethostbyname(socket.gethostname())
PORT = 4455
ADDR = (SERVER, PORT)
SIZE = 1024  # Increased buffer size for better data transfer
CHUNK_SIZE = 16  # Size for file data chunks
FORMAT = 'utf-8'
MAX_WORKERS = 5  # Maximum number of concurrent client handlers

# Priority queue for client connections
client_queue = queue.PriorityQueue()
shutdown_event = threading.Event()
executor = None

def handle_client(conn, addr):
    """ Handle a single client connection """
    thread_id = threading.current_thread().ident
    logging.info(f"[Thread {thread_id}] Started handling client {addr[0]}:{addr[1]}")
    
    try:
        # Receiving the filename, filesize and checksum from the client
        data = conn.recv(SIZE).decode(FORMAT)
        logging.info(f"[Thread {thread_id}] SERVER: [+] Received data: {data}")

        if "@" not in data:
            logging.error(f"[Thread {thread_id}] [!] Invalid data format received")
            conn.send("ERROR: Invalid data format".encode(FORMAT))
            return
        
        try:
            item = data.split("@")
            filename = item[0]
            filesize = int(item[1])
            original_md5 = item[2]
            logging.info(f"[Thread {thread_id}] [+] Filename: {filename}, Filesize: {filesize} bytes, Expected MD5: {original_md5}")
        except (IndexError, ValueError) as e:
            logging.error(f"[Thread {thread_id}] [!] Error parsing filename/filesize/checksum: {e}")
            conn.send("ERROR: Invalid filename or filesize".encode(FORMAT))
            return
        
        conn.send("Filename and filesize received".encode(FORMAT))

        """ Data transfer """
        bar = tqdm(range(filesize), f"[T{thread_id}] Receiving {filename} from {addr[0]}:{addr[1]}", unit="B", unit_scale=True, unit_divisor=CHUNK_SIZE)
        received_bytes = 0
        received_filename = f"server_received_{addr[0]}_{addr[1]}_{filename}" # Unique filename per client

        with open(received_filename, "w", encoding=FORMAT) as f:
            while received_bytes < filesize:
                try:
                    data = conn.recv(CHUNK_SIZE).decode(FORMAT)
                    
                    if not data:
                        logging.warning(f"[Thread {thread_id}] [!] No data received, connection might be closed")
                        break

                    f.write(data)
                    received_bytes += len(data)
                    conn.send("Data received.".encode(FORMAT))
                    bar.update(len(data))
                    
                except UnicodeDecodeError as e:
                    logging.error(f"[Thread {thread_id}] [!] Unicode decode error: {e}")
                    break
                except Exception as e:
                    logging.error(f"[Thread {thread_id}] [!] Error during data transfer: {e}")
                    break

        bar.close()
        logging.info(f"[Thread {thread_id}] [+] File transfer completed for {addr[0]}:{addr[1]}. Received {received_bytes}/{filesize} bytes")

        """ Check integrity after data transfer """
        logging.info(f"[Thread {thread_id}] SERVER: [+] Verifying file integrity for {received_filename}...")
        received_md5 = calculate_md5(received_filename)
        
        if received_md5 == original_md5:
            logging.info(f"[Thread {thread_id}] ✅ [+] FILE INTEGRITY VERIFIED for {addr[0]}:{addr[1]}! Checksums match.")
            conn.send("INTEGRITY_OK".encode(FORMAT))
        else:
            logging.error(f"[Thread {thread_id}] ❌ [!] FILE INTEGRITY FAILED for {addr[0]}:{addr[1]}! Checksums don't match.")
            logging.error(f"[Thread {thread_id}] [!] Expected: {original_md5}")
            logging.error(f"[Thread {thread_id}] [!] Received: {received_md5}")
            conn.send("INTEGRITY_FAILED".encode(FORMAT))

    except Exception as e:
        logging.error(f"[Thread {thread_id}] [!] Client {addr[0]}:{addr[1]} error: {e}")
    finally:
        try:
            conn.close()
        except:
            pass
        logging.info(f"[Thread {thread_id}] [+] Connection closed for {addr[0]}:{addr[1]}")
        logging.info(f"[Thread {thread_id}] Finished handling client {addr[0]}:{addr[1]}")

def process_client_queue():''
    """ Process clients from the priority queue using a thread pool, allowing multiple clients to be served simultaneously. """
    global executor
    
    try:
        executor = ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="ClientHandler")
        logging.info(f"[+] Thread pool initialized with {MAX_WORKERS} workers")
        
        while not shutdown_event.is_set(): # Continuously process clients until shutdown event is set
            try:
                # Get client from queue with timeout to check shutdown event
                priority, conn, addr = client_queue.get(timeout=1.0)
                logging.info(f"[+] Processing client {addr[0]}:{addr[1]} with priority {priority}")
                
                # Submit client handling to thread pool
                future = executor.submit(handle_client, conn, addr)
                
            except queue.Empty:
                # Timeout occurred, check shutdown event and continue
                continue
            except Exception as e:
                logging.error(f"[!] Error processing client queue: {e}")
                
    except Exception as e:
        logging.error(f"[!] Critical error in client queue processor: {e}")
    finally:
        if executor:
            logging.info("[+] Shutting down thread pool...")
            executor.shutdown(wait=True)
            logging.info("[+] Thread pool shutdown complete")

def signal_handler(signum, frame):
    """ Handle shutdown signals gracefully """
    logging.info(f"[+] Received signal {signum}, initiating graceful shutdown...")
    shutdown_event.set() # Set shutdown event to stop accepting new clients
    
    # Close any remaining items in queue
    try:
        while not client_queue.empty():
            try:
                _, conn, addr = client_queue.get_nowait()
                logging.info(f"[+] Closing pending connection from {addr[0]}:{addr[1]}")
                conn.close()
                client_queue.task_done()
            except queue.Empty:
                break
            except Exception as e:
                logging.error(f"[!] Error closing pending connection: {e}")
    except Exception as e:
        logging.error(f"[!] Error during queue cleanup: {e}")
    
    sys.exit(0)
        
def main():
    """ Creating a TCP server socket """
    global executor
    
    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Reuse address
    
    try:
        server.bind(ADDR)
        server.listen()
        logging.info(f"[+] Server listening on {SERVER}:{PORT}")

        """ Start thread to process client queue """
        queue_thread = threading.Thread(target=process_client_queue, name="QueueProcessor")
        queue_thread.start()

        """ Accepting connections from clients """
        while not shutdown_event.is_set():
            try:
                # Set timeout on accept to periodically check shutdown event
                server.settimeout(1.0)
                conn, addr = server.accept()
                
                if shutdown_event.is_set():
                    conn.close()
                    break
                    
                logging.info(f"SERVER: [+] Client connected from {addr[0]}:{addr[1]}")

                # Receive credentials to determine priority
                try:
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
                    
                except socket.timeout:
                    logging.warning(f"[!] Timeout receiving credentials from {addr[0]}:{addr[1]}")
                    conn.close()
                except Exception as e:
                    logging.error(f"[!] Error handling client {addr[0]}:{addr[1]}: {e}")
                    conn.close()
                    
            except socket.timeout:
                # Timeout on accept, continue to check shutdown event
                continue
            except Exception as e:
                if not shutdown_event.is_set():
                    logging.error(f"[!] Error accepting connections: {e}")
                break
    
    except Exception as e:
        logging.error(f"[!] Server error: {e}")
    finally:
        logging.info("[+] Server shutting down...")
        shutdown_event.set()
        
        # Close server socket
        try:
            server.close()
        except:
            pass
            
        # Wait for queue thread to finish
        if 'queue_thread' in locals():
            queue_thread.join(timeout=5.0)
            if queue_thread.is_alive():
                logging.warning("[!] Queue thread did not shutdown gracefully")
        
        logging.info("[+] Server closed")

if __name__ == "__main__":
    main()