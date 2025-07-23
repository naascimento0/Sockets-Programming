import os
import socket
from tqdm import tqdm
import logging
from checksum import calculate_md5
import threading
import time
import math
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SERVER = socket.gethostbyname(socket.gethostname())
PORT = 4455
ADDR = (SERVER, PORT)
SIZE = 1024 
CHUNK_SIZE = 1024 * 50   # 50KB - same as the server
BLOCK_SIZE = 1024 * 200  # 200KB - same as the server
FORMAT = 'utf-8'
FILENAME = "input/big_file.txt"
FILESIZE = os.path.getsize(FILENAME) if os.path.exists("big_file.txt") else 0
MAX_PARALLEL_BLOCKS = 4

USERNAME = "admin"  # Fixed credentials for testing
PASSWORD = "admin123"

def send_file_block(block_id, start_pos, block_size, filename, original_md5, total_blocks):
    """Send a specific block of the file to the server"""
    try:
        # Create new connection for this block
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(ADDR)
        
        # Send credentials
        credentials = f"{USERNAME}:{PASSWORD}"
        client.send(credentials.encode(FORMAT))
        
        # Receive authentication response
        auth_response = client.recv(SIZE).decode(FORMAT)
        if auth_response != "AUTH_OK":
            logging.error(f"[Block {block_id}] Authentication failed")
            return False
        
        # Send block metadata
        block_data = f"BLOCK@{filename}@{block_id}@{start_pos}@{block_size}@{total_blocks}@{original_md5}"
        client.send(block_data.encode(FORMAT))
        
        # Receive confirmation
        msg = client.recv(SIZE).decode(FORMAT)
        if "ERROR" in msg:
            logging.error(f"[Block {block_id}] Server error: {msg}")
            return False
        
        # Send block data
        with open(filename, "rb") as f:
            f.seek(start_pos) # Move to the start of the block
            sent_bytes = 0
            
            while sent_bytes < block_size:
                chunk_size = min(CHUNK_SIZE, block_size - sent_bytes) # 50KB
                data = f.read(chunk_size)
                
                if not data:
                    break
                    
                client.send(data)
                sent_bytes += len(data)
                
                # Wait for acknowledgment
                ack = client.recv(SIZE).decode(FORMAT)
                if "ERROR" in ack:
                    logging.error(f"[Block {block_id}] Transfer error: {ack}")
                    return False
        
        # Receive block completion confirmation
        completion = client.recv(SIZE).decode(FORMAT)
        success = "BLOCK_OK" in completion
        
        if success:
            logging.info(f"[Block {block_id}] Transfer completed successfully")
        else:
            logging.error(f"[Block {block_id}] Transfer failed: {completion}")
            
        client.close()
        return success
        
    except Exception as e:
        logging.error(f"[Block {block_id}] Error: {e}")
        return False

def main():
    """ TCP socket and connecting to the server with parallel block transfer """
    # Check if file exists
    if not os.path.exists(FILENAME):
        logging.error(f"[!] File {FILENAME} not found!")
        return
    
    filesize = os.path.getsize(FILENAME)
    
    if filesize == 0:
        logging.error(f"[!] File {FILENAME} is empty!")
        return

    # Calculate MD5 of original file
    logging.info("CLIENT: [+] Calculating MD5 checksum...")
    original_md5 = calculate_md5(FILENAME)
    if not original_md5:
        logging.error("[!] Failed to calculate MD5")
        return

    logging.info(f"CLIENT: [+] File: {FILENAME}, Size: {filesize} bytes")
    
    # Calculate blocks
    total_blocks = math.ceil(filesize / BLOCK_SIZE)
    logging.info(f"CLIENT: [+] Splitting file into {total_blocks} blocks of {BLOCK_SIZE} bytes each")
    
    try:
        # Create main connection to coordinate transfer
        coordinator = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        coordinator.connect(ADDR)
        logging.info(f"CLIENT: [+] Connected to server {SERVER}:{PORT}")

        # Send credentials for coordinator
        credentials = f"{USERNAME}:{PASSWORD}"
        coordinator.send(credentials.encode(FORMAT))
        
        # Receive authentication response
        auth_response = coordinator.recv(SIZE).decode(FORMAT)
        if auth_response != "AUTH_OK":
            logging.error("[!] Authentication failed")
            return

        # Send file metadata for coordination
        metadata = f"FILE_START@{FILENAME}@{filesize}@{total_blocks}@{original_md5}"
        coordinator.send(metadata.encode(FORMAT))
        
        # Receive coordination confirmation
        coord_response = coordinator.recv(SIZE).decode(FORMAT)
        if "ERROR" in coord_response:
            logging.error(f"[!] Coordination error: {coord_response}")
            return
        
        logging.info(f"[+] Server ready for parallel transfer")

        # Prepare blocks for parallel transfer
        blocks = []
        for block_id in range(total_blocks):
            start_pos = block_id * BLOCK_SIZE
            current_block_size = min(BLOCK_SIZE, filesize - start_pos)
            blocks.append((block_id, start_pos, current_block_size))

        # Send blocks in parallel
        successful_blocks = 0
        failed_blocks = []

        with ThreadPoolExecutor(max_workers=MAX_PARALLEL_BLOCKS) as executor: # Create up to 4 simultaneous threads
            # Create progress bar for overall transfer
            progress_bar = tqdm(total=filesize, desc="\nSending blocks", unit="B", unit_scale=True)
            
            # Submit all block transfer tasks
            future_to_block = {
                executor.submit(send_file_block, block_id, start_pos, block_size, 
                              FILENAME, original_md5, total_blocks): (block_id, block_size)
                for block_id, start_pos, block_size in blocks
            }
            
            # Process completed transfers
            for future in as_completed(future_to_block):
                block_id, block_size = future_to_block[future]
                try:
                    success = future.result()
                    if success:
                        successful_blocks += 1
                        progress_bar.update(block_size)
                    else:
                        failed_blocks.append(block_id)
                        logging.error(f"[!] Block {block_id} failed")
                except Exception as e:
                    failed_blocks.append(block_id)
                    logging.error(f"[!] Block {block_id} exception: {e}")
            
            progress_bar.close()

        logging.info(f"[+] Transfer completed: {successful_blocks}/{total_blocks} blocks successful")
        
        if failed_blocks:
            logging.error(f"[!] Failed blocks: {failed_blocks}")
            
        # Always signal transfer completion (even with failures) to let server verify integrity
        coordinator.send("TRANSFER_COMPLETE".encode(FORMAT))
        
        # Receive final integrity check result
        try:
            integrity_result = coordinator.recv(SIZE).decode(FORMAT)
            if "INTEGRITY_OK" in integrity_result:
                logging.info("[+] Server confirmed file integrity (checksum) is OK! ✅")
            elif "INTEGRITY_FAILED" in integrity_result:
                logging.error("[!] Server reported file integrity (checksum) failure! ❌")
            elif "ASSEMBLY_FAILED" in integrity_result:
                logging.error("[!] Server could not assemble file! ❌")
            else:
                logging.warning(f"[?] Unknown integrity response: {integrity_result}")
        except Exception as e:
            logging.error(f"[!] Error receiving integrity result: {e}")
        
        coordinator.close()
        
    except ConnectionRefusedError:
        logging.error(f"[!] Could not connect to server {SERVER}:{PORT}. Make sure server is running.")
    except Exception as e:
        logging.error(f"[!] Client error: {e}")
    finally:
        logging.info("[+] Client finished")

if __name__ == "__main__":
    main()