import os
import socket
import threading
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SERVER_IP = socket.gethostbyname(socket.gethostname())
PORT = 4466
ADDR = (SERVER_IP, PORT)
SIZE = 1024
FORMAT = "utf-8"
SERVER_DATA_PATH = "server_data"

# Create server directory if it does not exist
if not os.path.exists(SERVER_DATA_PATH):
    os.makedirs(SERVER_DATA_PATH)

"""
CMD@Msg
"""

def handle_client(conn, addr):
    """Handle communication with a client connection."""
    logging.info(f"[NEW CONNECTION] {addr} connected.")
    
    try:
        conn.send("OK@Welcome to the File Server".encode(FORMAT))

        while True:
            try:
                data = conn.recv(SIZE).decode(FORMAT)
                if not data:
                    break
                    
                data = data.split("@")
                cmd = data[0]

                if cmd == "HELP":
                    send_data = "OK@"
                    send_data += "LIST: List all the files from the server.\n"
                    send_data += "UPLOAD <path>: Upload a file to the server.\n"
                    send_data += "DELETE <filename>: Delete a file from the server.\n"
                    send_data += "LOGOUT: Disconnect from the server.\n"
                    send_data += "HELP: List all the commands."
                    conn.send(send_data.encode(FORMAT))
                    
                elif cmd == "LOGOUT":
                    conn.send("OK@Goodbye!".encode(FORMAT))
                    break

                elif cmd == "LIST":
                    try:
                        files = os.listdir(SERVER_DATA_PATH)
                        send_data = "OK@"
                        if len(files) == 0:
                            send_data += "The server directory is empty."
                        else:
                            send_data += "\n".join(f for f in files)
                        conn.send(send_data.encode(FORMAT))
                    except Exception as e:
                        send_data = f"ERROR@Failed to list files: {str(e)}"
                        conn.send(send_data.encode(FORMAT))

                elif cmd == "UPLOAD":
                    if len(data) >= 3:
                        name, text = data[1], data[2]
                        filepath = os.path.join(SERVER_DATA_PATH, name)
                        
                        try:
                            if os.path.exists(filepath):
                                send_data = f"ERROR@File {name} already exists."
                            else:
                                with open(filepath, "w", encoding=FORMAT) as f:
                                    f.write(text)
                                send_data = f"OK@File {name} uploaded successfully."
                        except Exception as e:
                            send_data = f"ERROR@Failed to upload file: {str(e)}"
                        
                        conn.send(send_data.encode(FORMAT))
                    else:
                        send_data = "ERROR@Invalid UPLOAD command format."
                        conn.send(send_data.encode(FORMAT))

                elif cmd == "DELETE":
                    if len(data) >= 2:
                        filename = data[1]
                        filepath = os.path.join(SERVER_DATA_PATH, filename)
                        
                        try:
                            files = os.listdir(SERVER_DATA_PATH)
                            if len(files) == 0:
                                send_data = "ERROR@The server directory is empty."
                            else:
                                if filename in files:
                                    os.remove(filepath)
                                    send_data = f"OK@File {filename} deleted successfully."
                                else:
                                    send_data = "ERROR@File not found."
                        except Exception as e:
                            send_data = f"ERROR@Failed to delete file: {str(e)}"
                        
                        conn.send(send_data.encode(FORMAT))
                    else:
                        send_data = "ERROR@Invalid DELETE command format."
                        conn.send(send_data.encode(FORMAT))
                        
                else:
                    send_data = "ERROR@Invalid command."
                    conn.send(send_data.encode(FORMAT))
                    
            except socket.error as e:
                logging.error(f"Socket error with {addr}: {e}")
                break
            except Exception as e:
                logging.error(f"Error handling client {addr}: {e}")
                break
                
    except Exception as e:
        logging.error(f"Error in handle_client for {addr}: {e}")
    finally:
        logging.info(f"[DISCONNECTED] {addr} disconnected")
        conn.close()


def main():
    """Main server function."""
    logging.info("[STARTING] Server is starting")
    
    try:
        # Creating a TCP connection because UDP doesn't check whether it's sent
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Avoid "[Errno 98] Address already in use"
        server.bind(ADDR)
        server.listen(5)  # Allow up to 5 pending connections
        logging.info(f"[LISTENING] Server is listening on {SERVER_IP}:{PORT}")

        while True:
            try:
                conn, addr = server.accept()
                thread = threading.Thread(target=handle_client, args=(conn, addr))
                thread.daemon = True  # Make thread daemon so it closes when main thread exits
                thread.start()
                logging.info(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")
            except KeyboardInterrupt:
                logging.info("[STOPPING] Server is shutting down...")
                break
            except Exception as e:
                logging.error(f"Error accepting connection: {e}")
                
    except Exception as e:
        logging.error(f"Server error: {e}")
    finally:
        if 'server' in locals():
            server.close()
        logging.info("[STOPPED] Server stopped")

if __name__ == "__main__":
    main()