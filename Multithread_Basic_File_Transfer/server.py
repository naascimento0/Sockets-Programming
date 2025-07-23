import os
import socket
import threading
import logging
import hashlib
import json
import time
import base64
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SERVER_IP = socket.gethostbyname(socket.gethostname())
PORT = 4466
ADDR = (SERVER_IP, PORT)
SIZE = 1024
FORMAT = "utf-8"
SERVER_DATA_PATH = "server_data"
CHUNK_SIZE = 8192  # Size of each chunk for parallel download
MAX_CONCURRENT_DOWNLOADS = 5  # Maximum concurrent downloads per client

# User database (in production, use a proper database)
USERS = {
    "admin": {"password": "admin123", "role": "admin", "priority": 1},
    "user1": {"password": "pass123", "role": "user", "priority": 2},
    "guest": {"password": "guest123", "role": "guest", "priority": 3}
}

# Active sessions
active_sessions = {}
download_queues = {"admin": [], "user": [], "guest": []}

# Create server directory if it does not exist
if not os.path.exists(SERVER_DATA_PATH):
    os.makedirs(SERVER_DATA_PATH)

"""
Enhanced File Server with Authentication and Parallel Downloads
CMD@Msg Protocol
"""

def calculate_file_checksum(filepath):
    """Calculate MD5 checksum of a file."""
    hash_md5 = hashlib.md5()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception as e:
        logging.error(f"Error calculating checksum for {filepath}: {e}")
        return None

def authenticate_user(username, password):
    """Authenticate user credentials."""
    if username in USERS and USERS[username]["password"] == password:
        return USERS[username]
    return None

def get_file_info(filepath):
    """Get file information including size and checksum."""
    try:
        file_size = os.path.getsize(filepath)
        checksum = calculate_file_checksum(filepath)
        return {
            "size": file_size,
            "checksum": checksum,
            "chunks": (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE  # Ceiling division
        }
    except Exception as e:
        logging.error(f"Error getting file info for {filepath}: {e}")
        return None

def send_file_chunk(filepath, chunk_index, chunk_size=CHUNK_SIZE):
    """Read and return a specific chunk of a file."""
    try:
        with open(filepath, "rb") as f:
            f.seek(chunk_index * chunk_size)
            chunk_data = f.read(chunk_size)
            return base64.b64encode(chunk_data).decode('utf-8')
    except Exception as e:
        logging.error(f"Error reading chunk {chunk_index} from {filepath}: {e}")
        return None

def handle_client(conn, addr):
    """Handle communication with a client connection."""
    logging.info(f"[NEW CONNECTION] {addr} connected.")
    
    session_id = f"{addr[0]}:{addr[1]}:{int(time.time())}"
    user_info = None
    authenticated = False
    
    try:
        conn.send("OK@Welcome to the Enhanced File Server! Please login.".encode(FORMAT))

        while True:
            try:
                data = conn.recv(SIZE).decode(FORMAT)
                if not data:
                    break
                    
                data = data.split("@")
                cmd = data[0]

                # Authentication required for most commands
                if not authenticated and cmd not in ["LOGIN", "HELP", "LOGOUT"]:
                    conn.send("ERROR@Please login first. Use: LOGIN <username> <password>".encode(FORMAT))
                    continue

                if cmd == "LOGIN":
                    if len(data) >= 3:
                        username, password = data[1], data[2]
                        user_info = authenticate_user(username, password)
                        if user_info:
                            authenticated = True
                            active_sessions[session_id] = {
                                "username": username,
                                "role": user_info["role"],
                                "priority": user_info["priority"],
                                "login_time": datetime.now()
                            }
                            send_data = f"OK@Login successful! Welcome {username} (Role: {user_info['role']})"
                            logging.info(f"[LOGIN] {username} logged in from {addr}")
                        else:
                            send_data = "ERROR@Invalid username or password."
                    else:
                        send_data = "ERROR@Usage: LOGIN <username> <password>"
                    conn.send(send_data.encode(FORMAT))

                elif cmd == "HELP":
                    send_data = "OK@Available commands:\n"
                    if authenticated:
                        send_data += "LIST: List all files from the server.\n"
                        send_data += "UPLOAD <path>: Upload a file to the server.\n"
                        send_data += "DOWNLOAD <filename>: Download a file from the server.\n"
                        send_data += "DOWNLOAD_PARALLEL <filename> <threads>: Download with multiple threads.\n"
                        send_data += "FILE_INFO <filename>: Get file information (size, checksum, chunks).\n"
                        send_data += "DELETE <filename>: Delete a file from the server.\n"
                        send_data += "WHOAMI: Show current user information.\n"
                    else:
                        send_data += "LOGIN <username> <password>: Login to the server.\n"
                    send_data += "LOGOUT: Disconnect from the server.\n"
                    send_data += "HELP: Show this help message."
                    conn.send(send_data.encode(FORMAT))

                elif cmd == "WHOAMI":
                    if session_id in active_sessions:
                        session = active_sessions[session_id]
                        send_data = f"OK@User: {session['username']}, Role: {session['role']}, Priority: {session['priority']}"
                    else:
                        send_data = "ERROR@Session not found."
                    conn.send(send_data.encode(FORMAT))
                    
                elif cmd == "LOGOUT":
                    if session_id in active_sessions:
                        username = active_sessions[session_id]["username"]
                        del active_sessions[session_id]
                        logging.info(f"[LOGOUT] {username} logged out from {addr}")
                    conn.send("OK@Goodbye!".encode(FORMAT))
                    break

                elif cmd == "LIST":
                    try:
                        files = os.listdir(SERVER_DATA_PATH)
                        send_data = "OK@"
                        if len(files) == 0:
                            send_data += "The server directory is empty."
                        else:
                            file_list = []
                            for f in files:
                                filepath = os.path.join(SERVER_DATA_PATH, f)
                                size = os.path.getsize(filepath)
                                file_list.append(f"{f} ({size} bytes)")
                            send_data += "\n".join(file_list)
                        conn.send(send_data.encode(FORMAT))
                    except Exception as e:
                        send_data = f"ERROR@Failed to list files: {str(e)}"
                        conn.send(send_data.encode(FORMAT))

                elif cmd == "FILE_INFO":
                    if len(data) >= 2:
                        filename = data[1]
                        filepath = os.path.join(SERVER_DATA_PATH, filename)
                        
                        if os.path.exists(filepath):
                            file_info = get_file_info(filepath)
                            if file_info:
                                info_json = json.dumps(file_info)
                                send_data = f"OK@{info_json}"
                            else:
                                send_data = "ERROR@Failed to get file information."
                        else:
                            send_data = "ERROR@File not found."
                    else:
                        send_data = "ERROR@Usage: FILE_INFO <filename>"
                    conn.send(send_data.encode(FORMAT))

                elif cmd == "DOWNLOAD_CHUNK":
                    if len(data) >= 3:
                        filename = data[1]
                        chunk_index = int(data[2])
                        filepath = os.path.join(SERVER_DATA_PATH, filename)
                        
                        if os.path.exists(filepath):
                            chunk_data = send_file_chunk(filepath, chunk_index)
                            if chunk_data:
                                send_data = f"OK@{chunk_data}"
                            else:
                                send_data = "ERROR@Failed to read chunk."
                        else:
                            send_data = "ERROR@File not found."
                    else:
                        send_data = "ERROR@Usage: DOWNLOAD_CHUNK <filename> <chunk_index>"
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
                        
                        # Check permissions
                        if session_id in active_sessions:
                            user_role = active_sessions[session_id]["role"]
                            if user_role not in ["admin", "user"]:
                                send_data = "ERROR@Insufficient permissions to delete files."
                                conn.send(send_data.encode(FORMAT))
                                continue
                        
                        try:
                            if os.path.exists(filepath):
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
        if session_id in active_sessions:
            username = active_sessions[session_id]["username"]
            del active_sessions[session_id]
            logging.info(f"[SESSION_ENDED] {username} session ended")
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