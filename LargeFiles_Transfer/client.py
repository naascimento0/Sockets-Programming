import os
import socket
from tqdm import tqdm
import logging
from checksum import calculate_md5

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SERVER = socket.gethostbyname(socket.gethostname())
PORT = 4455
ADDR = (SERVER, PORT)
SIZE = 1024 
CHUNK_SIZE = 16  # Size for file data chunks
FORMAT = 'utf-8'
FILENAME = "big_file.txt"
FILESIZE = os.path.getsize(FILENAME)

USERNAME = "admin"  # Fixed credentials for testing
PASSWORD = "admin123"

def main():
    """ TCP socket and connecting to the server """
    # Check if file exists
    if not os.path.exists(FILENAME):
        logging.error(f"[!] File {FILENAME} not found!")
        return
    
    filesize = os.path.getsize(FILENAME)

    # Calculate MD5 of original file
    logging.info("CLIENT: [+] Calculating MD5 checksum...")
    original_md5 = calculate_md5(FILENAME)
    if not original_md5:
        logging.error("[!] Failed to calculate MD5")
        return

    logging.info(f"CLIENT: [+] File: {FILENAME}, Size: {FILESIZE} bytes")
    
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(ADDR)
        logging.info(f"CLIENT: [+] Connected to server {SERVER}:{PORT}")

        """ Sending credentials """
        credentials = f"{USERNAME}:{PASSWORD}"
        client.send(credentials.encode(FORMAT))
        logging.info(f"CLIENT: [+] Sent credentials: {credentials}")

        """ Receive authentication response """
        auth_response = client.recv(SIZE).decode(FORMAT)
        logging.info(f"CLIENT: [+] SERVER: {auth_response}")
        if auth_response != "AUTH_OK":
            logging.error("[!] Authentication failed")
            return

        """ Sending filename, filesize and checksum to the server. """
        data = f"{FILENAME}@{FILESIZE}@{original_md5}"
        client.send(data.encode(FORMAT))
        logging.info(f"CLIENT: [+] Sent filename, filesize and MD5: {data}")
        
        # Receive confirmation from server
        msg = client.recv(SIZE).decode(FORMAT)
        logging.info(f"[+] SERVER: {msg}")
        
        if "ERROR" in msg:
            logging.error("[!] Server reported an error")
            return

        """ Data transfer. """
        bar = tqdm(range(FILESIZE), f"Sending {FILENAME}", unit="B", unit_scale=True, unit_divisor=CHUNK_SIZE)
        sent_bytes = 0

        with open(FILENAME, "r", encoding=FORMAT) as f:
            while sent_bytes < filesize:
                try:
                    data = f.read(CHUNK_SIZE)
                    
                    if not data:
                        logging.info("[+] End of file reached")
                        break

                    client.send(data.encode(FORMAT))
                    sent_bytes += len(data)
                    
                    # Wait for acknowledgment from server
                    msg = client.recv(SIZE).decode(FORMAT)
                    bar.update(len(data))
                    
                except UnicodeDecodeError as e:
                    logging.error(f"[!] Unicode decode error: {e}")
                    break
                except Exception as e:
                    logging.error(f"[!] Error during data transfer: {e}")
                    break

        bar.close()
        logging.info(f"[+] File transfer completed. Sent {sent_bytes}/{FILESIZE} bytes")

        # PASSO 5: Receber resultado da verificação de integridade
        try:
            integrity_result = client.recv(SIZE).decode(FORMAT)
            if "INTEGRITY_OK" in integrity_result:
                logging.info("[+] Server confirmed file integrity (checksum) is OK! ✅")
            elif "INTEGRITY_FAILED" in integrity_result:
                logging.error("[!] Server reported file integrity (checksum) failure! ❌")
            else:
                logging.warning(f"[?] Unknown integrity (checksum) response: {integrity_result}")
        except Exception as e:
            logging.error(f"[!] Error receiving integrity result: {e}")
        
    except ConnectionRefusedError:
        logging.error(f"[!] Could not connect to server {SERVER}:{PORT}. Make sure server is running.")
    except Exception as e:
        logging.error(f"[!] Client error: {e}")
    finally:
        """ Closing the connection """
        if 'client' in locals():
            client.close()
        logging.info("[+] Client closed")

if __name__ == "__main__":
    main()