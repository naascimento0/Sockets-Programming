import os
import socket
import logging
from checksum import calculate_md5
import threading
from auth import authenticate
import queue
from concurrent.futures import ThreadPoolExecutor
import signal
import sys
import time
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SERVER = socket.gethostbyname(socket.gethostname())
PORT = 4455
ADDR = (SERVER, PORT)
SIZE = 1024 # Buffer for control messages and metadata
CHUNK_SIZE = 1024 * 50  # 50KB chunks (size of each chunk sent by the client at a single operation send() / recv())
BLOCK_SIZE = 1024 * 200  # 200KB blocks (block size for parallel transfer)
FORMAT = 'utf-8'
MAX_WORKERS = 10  # Increased for parallel block handling

# Priority queue for client connections
client_queue = queue.PriorityQueue()
shutdown_event = threading.Event()
executor = None

# File transfer coordination
file_transfers = defaultdict(lambda: {
    'blocks': {},           # {block_id: block_data}
    'total_blocks': 0,      # How many blocks to expect
    'received_blocks': 0,   # How many blocks have been received
    'filesize': 0,          # Total file size
    'original_md5': '',     # MD5 for verification
    'coordinator_conn': None, # Main connection
    'lock': threading.Lock()  # Thread safety
})

# 1 thread for each file
# Initializes metadata
# Waits for signal
# Assembles final file
# Verifies integrity
# Cleans up resources
def handle_file_coordinator(conn, addr, filename, filesize, total_blocks, original_md5):
    """Handle the main file transfer coordination"""
    thread_id = threading.current_thread().ident
    transfer_key = f"{addr[0]}_{addr[1]}_{filename}" # Example: "192.168.1.100_54321_big_file.txt"
    
    try:
        logging.info(f"[Thread {thread_id}] Coordinating file transfer: {filename}")
        
        # Initialize transfer metadata
        with file_transfers[transfer_key]['lock']:
            file_transfers[transfer_key].update({
                'total_blocks': total_blocks,     # E.g., 10 blocks
                'received_blocks': 0,             # Starts at 0
                'filesize': filesize,             # E.g., 2MB
                'original_md5': original_md5,     # Original checksum
                'coordinator_conn': conn,         # This connection
                'blocks': {}                      # Empty dictionary for blocks
            })
        
        conn.send("COORDINATOR_READY".encode(FORMAT)) # Signal that coordinator is ready
        
        # Wait for transfer completion signal
        while True:
            try:
                signal = conn.recv(SIZE).decode(FORMAT)
                if "TRANSFER_COMPLETE" in signal:
                    logging.info(f"[Thread {thread_id}] Received transfer completion signal")
                    break
                elif "TRANSFER_FAILED" in signal:
                    logging.error(f"[Thread {thread_id}] Client reported transfer failure")
                    return
                else:
                    time.sleep(0.1)  # Short delay before checking again
            except socket.timeout:
                continue
            except Exception as e:
                logging.error(f"[Thread {thread_id}] Error waiting for completion: {e}")
                return
        
        # Assemble file from blocks
        logging.info(f"[Thread {thread_id}] Assembling file from {total_blocks} blocks...")
        assembled_filename = f"server_received_{addr[0]}_{addr[1]}_{filename}"
        
        success = assemble_file_from_blocks(transfer_key, assembled_filename, total_blocks)
        
        if success:
            # Verify file integrity
            logging.info(f"[Thread {thread_id}] Verifying file integrity...")
            received_md5 = calculate_md5(assembled_filename)
            
            if received_md5 == original_md5:
                logging.info(f"[Thread {thread_id}] ✅ FILE INTEGRITY VERIFIED! Checksums match.")
                conn.send("INTEGRITY_OK".encode(FORMAT))
            else:
                logging.error(f"[Thread {thread_id}] ❌ FILE INTEGRITY FAILED! Checksums don't match.")
                logging.error(f"[Thread {thread_id}] Expected: {original_md5}")
                logging.error(f"[Thread {thread_id}] Received: {received_md5}")
                conn.send("INTEGRITY_FAILED".encode(FORMAT))
        else:
            conn.send("ASSEMBLY_FAILED".encode(FORMAT))
            
    except Exception as e:
        logging.error(f"[Thread {thread_id}] Coordinator error: {e}")
    finally:
        # Cleanup transfer metadata
        if transfer_key in file_transfers:
            del file_transfers[transfer_key]
        logging.info(f"[Thread {thread_id}] File coordinator finished")

# Multiple threads
# This function receives a specific block of the file (e.g., Block 2 from 0-200KB) divided into smaller chunks (50KB each), allowing parallel transfer with other threads.
# Receives block metadata
# Receives chunks sequentially
# Assembles the complete block
# Validates block integrity
# Stores in shared dictionary
# Confirms success
def handle_block_transfer(conn, addr, filename, block_id, start_pos, block_size, total_blocks, original_md5):
    """Handle individual block transfer"""
    import math
    thread_id = threading.current_thread().ident
    transfer_key = f"{addr[0]}_{addr[1]}_{filename}" # Same key as in coordinator
    
    try:
        expected_chunks = math.ceil(block_size / CHUNK_SIZE)
        logging.info(f"[Thread {thread_id}] Receiving block {block_id}/{total_blocks-1} ({expected_chunks} chunks expected)")
        
        # Aumentar timeout para blocos com mais chunks
        conn.settimeout(45.0)
        conn.send("BLOCK_READY".encode(FORMAT))
        
        # Receive block data
        block_data = bytearray()
        received_bytes = 0
        
        while received_bytes < block_size:
            chunk_size = min(CHUNK_SIZE, block_size - received_bytes) # Last chunk may be smaller
            data = conn.recv(chunk_size)
            
            if not data:
                logging.warning(f"[Thread {thread_id}] No data received for block {block_id}")
                conn.send("NACK".encode(FORMAT))
                break
                
            if len(data) != chunk_size:
                logging.error(f"[Thread {thread_id}] Chunk size mismatch: expected {chunk_size}, got {len(data)}")
                conn.send("NACK".encode(FORMAT))
                break
                
            block_data.extend(data)
            received_bytes += len(data)
                    
            conn.send("ACK".encode(FORMAT))  # ACK only for valid chunks
            time.sleep(0.2)
        
        if received_bytes == block_size:
            # Store block in transfer metadata
            with file_transfers[transfer_key]['lock']: # Ensure thread safety with lock (each chunk is processed by a different thread)
                file_transfers[transfer_key]['blocks'][block_id] = bytes(block_data)
                file_transfers[transfer_key]['received_blocks'] += 1
                current_blocks = file_transfers[transfer_key]['received_blocks'] # How many blocks have been received so far
            
            logging.info(f"[Thread {thread_id}] ✅ Block {block_id} COMPLETED! ({current_blocks}/{total_blocks} blocks total)\n")
            conn.send("BLOCK_OK".encode(FORMAT))
        else:
            logging.error(f"[Thread {thread_id}] ❌ Block {block_id} size mismatch: expected {block_size}, got {received_bytes}\n")
            conn.send("BLOCK_ERROR".encode(FORMAT))
            
    except Exception as e:
        logging.error(f"[Thread {thread_id}] Block transfer error: {e}")
        conn.send("BLOCK_ERROR".encode(FORMAT))

# Example:
# transfer_key = "192.168.1.100_12345_big_file.txt"
# output_filename = "server_received_192.168.1.100_12345_big_file.txt"  
# total_blocks = 5  # 1MB file ÷ 200KB = 5 blocks
def assemble_file_from_blocks(transfer_key, output_filename, total_blocks):
    """Assemble the complete file from received blocks"""
    try:
        with open(output_filename, "wb") as f:
            for block_id in range(total_blocks):
                if block_id in file_transfers[transfer_key]['blocks']: # Check if block exists
                    block_data = file_transfers[transfer_key]['blocks'][block_id] # Get the block data
                    f.write(block_data) # Write the block data to the file
                else:
                    logging.error(f"Missing block {block_id} for {transfer_key}")
                    return False
        
        logging.info(f"File {output_filename} assembled successfully from {total_blocks} blocks")
        return True
        
    except Exception as e:
        logging.error(f"Error assembling file: {e}")
        return False

def handle_client(conn, addr):
    """ Handle a single client connection """
    thread_id = threading.current_thread().ident
    logging.info(f"[Thread {thread_id}] Started handling client {addr[0]}:{addr[1]}")
    
    try:
        # Receiving the data from the client
        data = conn.recv(SIZE).decode(FORMAT)
        logging.info(f"[Thread {thread_id}] SERVER: [+] Received data: {data}")

        if "@" not in data:
            logging.error(f"[Thread {thread_id}] [!] Invalid data format received")
            conn.send("ERROR: Invalid data format".encode(FORMAT))
            return
        
        parts = data.split("@")
        command = parts[0]
        
        if command == "FILE_START":
            # File coordination request, extracting file metadata
            try:
                filename = parts[1] # "big_file.txt"
                filesize = int(parts[2]) # # 1048576 (1MB)
                total_blocks = int(parts[3]) # 5 blocks
                original_md5 = parts[4] # "abc123..."

                logging.info(f"[Thread {thread_id}] File coordination: {filename}, {filesize} bytes, {total_blocks} blocks")
                handle_file_coordinator(conn, addr, filename, filesize, total_blocks, original_md5)
                
            except (IndexError, ValueError) as e:
                logging.error(f"[Thread {thread_id}] Error parsing file coordination data: {e}")
                conn.send("ERROR: Invalid coordination data".encode(FORMAT))
                
        elif command == "BLOCK":
            # Block transfer request, extracting block metadata
            try:
                filename = parts[1]        # "big_file.txt"
                block_id = int(parts[2])   # 2 (block number 2)
                start_pos = int(parts[3])  # 400000 (start position)
                block_size = int(parts[4]) # 200000 (200KB)
                total_blocks = int(parts[5]) # 5 blocks total
                original_md5 = parts[6]    # "abc123..."
                
                logging.info(f"[Thread {thread_id}] Block transfer: {filename}, block {block_id}")
                handle_block_transfer(conn, addr, filename, block_id, start_pos, block_size, total_blocks, original_md5)
                
            except (IndexError, ValueError) as e:
                logging.error(f"[Thread {thread_id}] Error parsing block data: {e}")
                conn.send("ERROR: Invalid block data".encode(FORMAT))
        else:
            # Unknown command
            logging.error(f"[Thread {thread_id}] Unknown command: {command}")
            conn.send("ERROR: Unknown command. Use FILE_START or BLOCK".encode(FORMAT))

    except Exception as e:
        logging.error(f"[Thread {thread_id}] [!] Client {addr[0]}:{addr[1]} error: {e}")
    finally:
        try:
            conn.close()
        except:
            pass
        logging.info(f"[Thread {thread_id}] [+] Connection closed for {addr[0]}:{addr[1]}")

def process_client_queue():
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