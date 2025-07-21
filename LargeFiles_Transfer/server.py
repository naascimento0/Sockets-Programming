import os
import socket
from tqdm import tqdm
import logging
from checksum import calculate_md5

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SERVER = socket.gethostbyname(socket.gethostname())
PORT = 4455
ADDR = (SERVER, PORT)
SIZE = 1024  # Increased buffer size for better data transfer
CHUNK_SIZE = 16  # Size for file data chunks
FORMAT = 'utf-8'

def main():
    """ Creating a TCP server socket """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Reuse address
    server.bind(ADDR)
    server.listen()
    logging.info(f"[+] Server listening on {SERVER}:{PORT}")

    try:
        """ Accepting the connection from the client. """
        conn, addr = server.accept()
        logging.info(f"[+] Client connected from {addr[0]}:{addr[1]}")

        """ Receiving the filename and filesize from the client. """
        data = conn.recv(SIZE).decode(FORMAT)
        logging.info(f"[+] Received data: {data}")
        
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
        bar = tqdm(range(filesize), f"Receiving {filename}", unit="B", unit_scale=True, unit_divisor=CHUNK_SIZE)
        received_bytes = 0
        received_filename = f"server_received_{filename}"

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
        logging.info(f"[+] File transfer completed. Received {received_bytes}/{filesize} bytes")

        # Verificar integridade após transferência
        logging.info("[+] Verifying file integrity...")
        received_md5 = calculate_md5(received_filename)
        
        if received_md5 == original_md5:
            logging.info("✅ [+] FILE INTEGRITY VERIFIED! Checksums match.")
            conn.send("INTEGRITY_OK".encode(FORMAT))
        else:
            logging.error("❌ [!] FILE INTEGRITY FAILED! Checksums don't match.")
            logging.error(f"[!] Expected: {original_md5}")
            logging.error(f"[!] Received: {received_md5}")
            conn.send("INTEGRITY_FAILED".encode(FORMAT))
        
    except Exception as e:
        logging.error(f"[!] Server error: {e}")
    finally:
        """ Closing connection. """
        if 'conn' in locals():
            conn.close()
        server.close()
        logging.info("[+] Server closed")


if __name__ == "__main__":
    main()