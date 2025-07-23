import os
import socket
from tqdm import tqdm
import logging
from checksum import calculate_md5
import threading
import time
import math
import signal
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# ANSI color codes for terminal output
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Global variables for graceful shutdown
shutdown_event = threading.Event()
executor = None
coordinator_conn = None

SERVER = socket.gethostbyname(socket.gethostname())
PORT = 4455
ADDR = (SERVER, PORT)
SIZE = 1024 
CHUNK_SIZE = 1024 * 50   # 50KB - same as the server
BLOCK_SIZE = 1024 * 200  # 200KB - same as the server
FORMAT = 'utf-8'
FILENAME = "input/big_file.txt"
FILESIZE = os.path.getsize(FILENAME) if os.path.exists(FILENAME) else 0
MAX_PARALLEL_BLOCKS = 4

USERNAME = "admin"  # Fixed credentials for testing
PASSWORD = "admin123"

# Statistics for monitoring transfer quality
transfer_stats = {
    'nacks_received': 0,
    'retries_attempted': 0,
    'chunks_failed': 0,
    'lock': threading.Lock()
}

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    logging.info(f"{Colors.YELLOW}[CLIENT]{Colors.RESET} Received signal {signum}, initiating graceful shutdown...")
    shutdown_event.set()
    
    # Close coordinator connection if exists
    global coordinator_conn
    if coordinator_conn:
        try:
            coordinator_conn.send("TRANSFER_FAILED".encode(FORMAT))
            coordinator_conn.close()
            logging.info(f"{Colors.YELLOW}[CLIENT]{Colors.RESET} Coordinator connection closed")
        except:
            pass
    
    # Shutdown executor if exists
    global executor
    if executor:
        logging.info(f"{Colors.YELLOW}[CLIENT]{Colors.RESET} Shutting down thread pool...")
        executor.shutdown(wait=False)
    
    # Display final statistics
    with transfer_stats['lock']:
        if transfer_stats['nacks_received'] > 0 or transfer_stats['chunks_failed'] > 0:
            logging.info(f"{Colors.CYAN}[TRANSFER STATS]{Colors.RESET}")
            logging.info(f"  NACKs received: {Colors.RED}{transfer_stats['nacks_received']}{Colors.RESET}")
            logging.info(f"  Chunks failed: {Colors.RED}{transfer_stats['chunks_failed']}{Colors.RESET}")
            logging.info(f"  Retries attempted: {Colors.YELLOW}{transfer_stats['retries_attempted']}{Colors.RESET}")
    
    logging.info(f"{Colors.YELLOW}[CLIENT]{Colors.RESET} Shutdown complete")
    sys.exit(0)

def send_file_block(block_id, start_pos, block_size, filename, original_md5, total_blocks):
    """Send a specific block of the file to the server"""
    max_retries = 3
    retry_count = 0
    
    while retry_count < max_retries:
        if shutdown_event.is_set():
            logging.warning(f"{Colors.YELLOW}[Block {block_id}]{Colors.RESET} Shutdown requested, aborting transfer")
            return False
            
        try:
            # Create new connection for this block
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(30.0)  # Set timeout for socket operations
            client.connect(ADDR)
            
            # Send credentials
            credentials = f"{USERNAME}:{PASSWORD}"
            client.send(credentials.encode(FORMAT))
            
            # Receive authentication response
            auth_response = client.recv(SIZE).decode(FORMAT)
            if auth_response != "AUTH_OK":
                logging.error(f"{Colors.RED}[Block {block_id}]{Colors.RESET} Authentication failed")
                client.close()
                return False
            
            # Send block metadata
            block_data = f"BLOCK@{filename}@{block_id}@{start_pos}@{block_size}@{total_blocks}@{original_md5}"
            client.send(block_data.encode(FORMAT))
            
            # Receive confirmation
            msg = client.recv(SIZE).decode(FORMAT)
            if "ERROR" in msg:
                logging.error(f"{Colors.RED}[Block {block_id}]{Colors.RESET} Server error: {msg}")
                client.close()
                return False
            
            # Send block data with NACK handling
            chunk_failures = 0
            total_chunks = math.ceil(block_size / CHUNK_SIZE)
            
            with open(filename, "rb") as f:
                f.seek(start_pos) # Move to the start of the block
                sent_bytes = 0
                
                while sent_bytes < block_size:
                    if shutdown_event.is_set():
                        client.close()
                        return False
                        
                    chunk_size = min(CHUNK_SIZE, block_size - sent_bytes) # 50KB
                    data = f.read(chunk_size)
                    
                    if not data:
                        break
                        
                    client.send(data)
                    sent_bytes += len(data)
                    
                    # Wait for acknowledgment
                    try:
                        ack = client.recv(SIZE).decode(FORMAT)
                        
                        if "NACK" in ack:
                            # Handle NACK - server rejected this chunk
                            chunk_failures += 1
                            with transfer_stats['lock']:
                                transfer_stats['nacks_received'] += 1
                                transfer_stats['chunks_failed'] += 1
                            
                            
                            logging.warning(f"{Colors.YELLOW}[Block {block_id}]{Colors.RESET} {Colors.RED}NACK received{Colors.RESET} for chunk at position {sent_bytes - len(data)} (chunk {math.ceil(sent_bytes/CHUNK_SIZE)}/{total_chunks})")

                            # TEST: Abort block transfer on NACK instead of retrying
                            # logging.error(f"{Colors.RED}[Block {block_id}]{Colors.RESET} Aborting block due to NACK (test mode)")
                            # client.close()
                            # return False

                            # Move file pointer back to retry this chunk
                            f.seek(start_pos + sent_bytes - len(data))
                            sent_bytes -= len(data)
                            
                            # If too many chunk failures, abort this block
                            if chunk_failures >= 5:
                                logging.error(f"{Colors.RED}[Block {block_id}]{Colors.RESET} Too many chunk failures ({chunk_failures}), aborting block")
                                client.close()
                                return False
                                
                            time.sleep(0.1)  # Brief delay before retry
                            continue
                            
                        if "BLOCK_ERROR" in ack:
                            logging.error(f"{Colors.RED}[Block {block_id}]{Colors.RESET} Server block error: {ack}")
                            client.close()
                            return False
                        elif ack not in ["ACK", "NACK"]:
                            logging.warning(f"{Colors.YELLOW}[Block {block_id}]{Colors.RESET} Unexpected chunk response: {ack}")
                    
                    except socket.timeout:
                        logging.warning(f"{Colors.YELLOW}[Block {block_id}]{Colors.RESET} Timeout waiting for ACK")
                        chunk_failures += 1
                        if chunk_failures >= 5:
                            client.close()
                            break
            
            # Receive block completion confirmation
            try:
                completion = client.recv(SIZE).decode(FORMAT)
                success = "BLOCK_OK" in completion
                
                if success:
                    if chunk_failures > 0:
                        logging.info(f"{Colors.GREEN}[Block {block_id}]{Colors.RESET} Transfer completed successfully {Colors.YELLOW}({chunk_failures} chunk retries){Colors.RESET}")
                    else:
                        logging.info(f"{Colors.GREEN}[Block {block_id}]{Colors.RESET} Transfer completed successfully")
                else:
                    logging.error(f"{Colors.RED}[Block {block_id}]{Colors.RESET} Transfer failed: {completion}")
                    
                client.close()
                return success
                
            except socket.timeout:
                logging.error(f"{Colors.RED}[Block {block_id}]{Colors.RESET} Timeout waiting for block completion")
                client.close()
                return False
            
        except Exception as e:
            logging.error(f"{Colors.RED}[Block {block_id}]{Colors.RESET} Error (attempt {retry_count + 1}/{max_retries}): {e}")
            retry_count += 1

            with transfer_stats['lock']:
                transfer_stats['retries_attempted'] += 1
            
            if retry_count < max_retries:
                logging.info(f"{Colors.YELLOW}[Block {block_id}]{Colors.RESET} Retrying in 2 seconds...")
                time.sleep(2)
            else:
                logging.error(f"{Colors.RED}[Block {block_id}]{Colors.RESET} Max retries reached, giving up")
                return False
    
    return False

def main():
    """ TCP socket and connecting to the server with parallel block transfer """
    global coordinator_conn, executor
    
    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Check if file exists
    if not os.path.exists(FILENAME):
        logging.error(f"{Colors.RED}[!] File {FILENAME} not found!{Colors.RESET}")
        return
    
    filesize = os.path.getsize(FILENAME)
    
    if filesize == 0:
        logging.error(f"{Colors.RED}[!] File {FILENAME} is empty!{Colors.RESET}")
        return

    # Calculate MD5 of original file
    logging.info(f"{Colors.CYAN}CLIENT: [+] Calculating MD5 checksum...{Colors.RESET}")
    original_md5 = calculate_md5(FILENAME)
    if not original_md5:
        logging.error(f"{Colors.RED}[!] Failed to calculate MD5{Colors.RESET}")
        return

    logging.info(f"{Colors.CYAN}CLIENT: [+] File: {Colors.BOLD}{FILENAME}{Colors.RESET}, Size: {filesize} bytes")
    
    # Calculate blocks
    total_blocks = math.ceil(filesize / BLOCK_SIZE)
    logging.info(f"{Colors.CYAN}CLIENT: [+] Splitting file into {total_blocks} blocks of {BLOCK_SIZE} bytes each{Colors.RESET}")
    
    try:
        # Create main connection to coordinate transfer
        coordinator_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        coordinator_conn.settimeout(60.0)  # Set timeout for coordinator
        coordinator_conn.connect(ADDR)
        logging.info(f"{Colors.CYAN}CLIENT: [+] Connected to server {SERVER}:{PORT}{Colors.RESET}")

        # Send credentials for coordinator
        credentials = f"{USERNAME}:{PASSWORD}"
        coordinator_conn.send(credentials.encode(FORMAT))
        
        # Receive authentication response
        auth_response = coordinator_conn.recv(SIZE).decode(FORMAT)
        if auth_response != "AUTH_OK":
            logging.error(f"{Colors.RED}[!] Authentication failed{Colors.RESET}")
            return

        # Send file metadata for coordination
        metadata = f"FILE_START@{FILENAME}@{filesize}@{total_blocks}@{original_md5}"
        coordinator_conn.send(metadata.encode(FORMAT))
        
        # Receive coordination confirmation
        coord_response = coordinator_conn.recv(SIZE).decode(FORMAT)
        if "ERROR" in coord_response:
            logging.error(f"{Colors.RED}[!] Coordination error: {coord_response}{Colors.RESET}")
            return
        
        logging.info(f"{Colors.GREEN}[+] Server ready for parallel transfer{Colors.RESET}")

        # Prepare blocks for parallel transfer
        blocks = []
        for block_id in range(total_blocks):
            start_pos = block_id * BLOCK_SIZE
            current_block_size = min(BLOCK_SIZE, filesize - start_pos)
            blocks.append((block_id, start_pos, current_block_size))

        # Send blocks in parallel
        successful_blocks = 0
        failed_blocks = []

        executor = ThreadPoolExecutor(max_workers=MAX_PARALLEL_BLOCKS) # Create up to 4 simultaneous threads
        
        try:
            # Create progress bar for overall transfer
            progress_bar = tqdm(total=filesize, desc=f"\n{Colors.BLUE}Sending blocks{Colors.RESET}", 
                              unit="B", unit_scale=True, disable=shutdown_event.is_set())
            
            # Submit all block transfer tasks
            future_to_block = {
                executor.submit(send_file_block, block_id, start_pos, block_size, 
                              FILENAME, original_md5, total_blocks): (block_id, block_size)
                for block_id, start_pos, block_size in blocks
            }
            
            # Process completed transfers
            for future in as_completed(future_to_block):
                if shutdown_event.is_set():
                    logging.info(f"{Colors.YELLOW}[!] Shutdown requested, stopping transfer{Colors.RESET}")
                    break
                    
                block_id, block_size = future_to_block[future]
                try:
                    success = future.result()
                    if success:
                        successful_blocks += 1
                        progress_bar.update(block_size)
                    else:
                        failed_blocks.append(block_id)
                        logging.error(f"{Colors.RED}[!] Block {block_id} failed{Colors.RESET}")
                except Exception as e:
                    failed_blocks.append(block_id)
                    logging.error(f"{Colors.RED}[!] Block {block_id} exception: {e}{Colors.RESET}")
            
            progress_bar.close()

        finally:
            executor.shutdown(wait=True)

        if shutdown_event.is_set():
            logging.info(f"{Colors.YELLOW}[+] Transfer interrupted by shutdown{Colors.RESET}")
            coordinator_conn.send("TRANSFER_FAILED".encode(FORMAT))
            return

        logging.info(f"{Colors.GREEN}[+] Transfer completed: {successful_blocks}/{total_blocks} blocks successful{Colors.RESET}")
        
        if failed_blocks:
            logging.error(f"{Colors.RED}[!] Failed blocks: {failed_blocks}{Colors.RESET}")
            
        # Display transfer statistics
        with transfer_stats['lock']:
            if transfer_stats['nacks_received'] > 0 or transfer_stats['chunks_failed'] > 0:
                logging.info(f"\n{Colors.CYAN}[TRANSFER STATISTICS]{Colors.RESET}")
                logging.info(f"  Total NACKs received: {Colors.RED}{transfer_stats['nacks_received']}{Colors.RESET}")
                logging.info(f"  Chunks that failed: {Colors.RED}{transfer_stats['chunks_failed']}{Colors.RESET}")
                logging.info(f"  Block retries attempted: {Colors.YELLOW}{transfer_stats['retries_attempted']}{Colors.RESET}")
                
                if transfer_stats['nacks_received'] > 0:
                    logging.info(f"  {Colors.YELLOW}ℹ️  NACKs indicate network issues or data corruption during transfer{Colors.RESET}")
                    
        # Always signal transfer completion (even with failures) to let server verify integrity
        coordinator_conn.send("TRANSFER_COMPLETE".encode(FORMAT))
        
        # Receive final integrity check result
        try:
            integrity_result = coordinator_conn.recv(SIZE).decode(FORMAT)
            if "INTEGRITY_OK" in integrity_result:
                logging.info(f"{Colors.GREEN}[+] Server confirmed file integrity (checksum) is OK! ✅{Colors.RESET}")
            elif "INTEGRITY_FAILED" in integrity_result:
                logging.error(f"{Colors.RED}[!] Server reported file integrity (checksum) failure! ❌{Colors.RESET}")
            elif "ASSEMBLY_FAILED" in integrity_result:
                logging.error(f"{Colors.RED}[!] Server could not assemble file! ❌{Colors.RESET}")
            else:
                logging.warning(f"{Colors.YELLOW}[?] Unknown integrity response: {integrity_result}{Colors.RESET}")
        except Exception as e:
            logging.error(f"{Colors.RED}[!] Error receiving integrity result: {e}{Colors.RESET}")
        
        coordinator_conn.close()
        coordinator_conn = None
        
    except ConnectionRefusedError:
        logging.error(f"{Colors.RED}[!] Could not connect to server {SERVER}:{PORT}. Make sure server is running.{Colors.RESET}")
    except Exception as e:
        logging.error(f"{Colors.RED}[!] Client error: {e}{Colors.RESET}")
    finally:
        # Final cleanup
        if coordinator_conn:
            try:
                coordinator_conn.close()
            except:
                pass
        logging.info(f"{Colors.GREEN}[+] Client finished{Colors.RESET}")

if __name__ == "__main__":
    main()