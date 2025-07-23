import os
import socket
import sys
import threading
import json
import hashlib
import base64
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

SERVER_IP = socket.gethostbyname(socket.gethostname())
PORT = 4466
ADDR = (SERVER_IP, PORT)
SIZE = 1024
FORMAT = "utf-8"
CHUNK_SIZE = 8192

# Global variables for session management
authenticated = False
username = None
client_socket = None

def print_help():
    """Print available commands."""
    print("\nAvailable commands:")
    if authenticated:
        print("HELP - Show this help message")
        print("LIST - List all files on the server") 
        print("UPLOAD <filepath> - Upload a file to the server")
        print("DOWNLOAD <filename> - Download a file from the server")
        print("DOWNLOAD_PARALLEL <filename> <threads> - Download file using multiple threads")
        print("FILE_INFO <filename> - Get file information (size, checksum, chunks)")
        print("DELETE <filename> - Delete a file from the server")
        print("WHOAMI - Show current user information")
        print("LOGOUT - Disconnect from the server")
    else:
        print("LOGIN <username> <password> - Login to the server")
        print("HELP - Show this help message")
        print("LOGOUT - Disconnect from the server")
    print()

def calculate_file_checksum(filepath):
    """Calculate MD5 checksum of a file."""
    hash_md5 = hashlib.md5()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception as e:
        print(f"Error calculating checksum: {e}")
        return None

def send_command(client, command):
    """Send command to server and get response."""
    try:
        client.send(command.encode(FORMAT))
        response = client.recv(SIZE).decode(FORMAT)
        return parse_response(response)
    except Exception as e:
        print(f"Error sending command: {e}")
        return "ERROR", str(e)

def download_chunk(filename, chunk_index, credentials, max_retries=3):
    """Download a specific chunk of a file."""
    username, password = credentials
    
    for attempt in range(max_retries):
        try:
            # Create new connection for this chunk
            chunk_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            chunk_client.connect(ADDR)
            
            # Wait for welcome message
            welcome = chunk_client.recv(SIZE).decode(FORMAT)
            
            # Authenticate with the chunk connection
            login_cmd = f"LOGIN@{username}@{password}"
            chunk_client.send(login_cmd.encode(FORMAT))
            login_response = chunk_client.recv(SIZE).decode(FORMAT)
            
            login_cmd_resp, login_msg = parse_response(login_response)
            if login_cmd_resp != "OK":
                print(f"Authentication failed for chunk {chunk_index}: {login_msg}")
                chunk_client.close()
                if attempt == max_retries - 1:
                    return chunk_index, None
                continue
                
            # Request the chunk
            chunk_cmd = f"DOWNLOAD_CHUNK@{filename}@{chunk_index}"
            chunk_client.send(chunk_cmd.encode(FORMAT))
            
            response = chunk_client.recv(SIZE * 10).decode(FORMAT)  # Larger buffer for chunk data
            cmd, data = parse_response(response)
            
            chunk_client.close()
            
            if cmd == "OK":
                return chunk_index, base64.b64decode(data.encode('utf-8'))
            else:
                print(f"Error downloading chunk {chunk_index}: {data}")
                if attempt == max_retries - 1:
                    return chunk_index, None
                time.sleep(0.1 * (attempt + 1))  # Exponential backoff
                
        except Exception as e:
            print(f"Attempt {attempt + 1} failed for chunk {chunk_index}: {e}")
            if attempt == max_retries - 1:
                return chunk_index, None
            time.sleep(0.1 * (attempt + 1))
    
    return chunk_index, None

def download_file_parallel(filename, num_threads=4):
    """Download a file using multiple threads."""
    global username, client_socket
    
    print(f"Getting file information for {filename}...")
    
    # Get file info first
    cmd, response = send_command(client_socket, f"FILE_INFO@{filename}")
    if cmd != "OK":
        print(f"Error getting file info: {response}")
        return False
    
    try:
        file_info = json.loads(response)
        file_size = file_info["size"]
        expected_checksum = file_info["checksum"]
        total_chunks = file_info["chunks"]
        
        print(f"File size: {file_size} bytes")
        print(f"Total chunks: {total_chunks}")
        print(f"Expected checksum: {expected_checksum}")
        print(f"Starting download with {num_threads} threads...")
        
        # Get user credentials for chunk downloads
        password = getattr(client_socket, 'password', '')
        credentials = (username, password)
        
        chunks_data = [None] * total_chunks
        
        # Download chunks in parallel
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            # Submit all chunk download tasks
            future_to_chunk = {
                executor.submit(download_chunk, filename, i, credentials): i 
                for i in range(total_chunks)
            }
            
            completed = 0
            for future in as_completed(future_to_chunk):
                chunk_index, chunk_data = future.result()
                if chunk_data is not None:
                    chunks_data[chunk_index] = chunk_data
                    completed += 1
                    progress = (completed / total_chunks) * 100
                    print(f"Progress: {progress:.1f}% ({completed}/{total_chunks} chunks)")
                else:
                    print(f"Failed to download chunk {chunk_index}")
                    return False
        
        # Reconstruct the file
        print("Reconstructing file...")
        output_path = f"downloaded_{filename}"
        
        with open(output_path, "wb") as f:
            for chunk_data in chunks_data:
                if chunk_data:
                    f.write(chunk_data)
        
        # Verify integrity
        print("Verifying file integrity...")
        actual_checksum = calculate_file_checksum(output_path)
        
        if actual_checksum == expected_checksum:
            print(f"✅ Download successful! File saved as: {output_path}")
            print(f"✅ Checksum verified: {actual_checksum}")
            return True
        else:
            print(f"❌ Checksum mismatch!")
            print(f"Expected: {expected_checksum}")
            print(f"Actual: {actual_checksum}")
            return False
            
    except json.JSONDecodeError as e:
        print(f"Error parsing file info: {e}")
        return False
    except Exception as e:
        print(f"Error during parallel download: {e}")
        return False

def handle_upload(client, filepath):
    """Handle file upload command."""
    try:
        if os.path.exists(filepath):
            with open(filepath, "r", encoding=FORMAT) as f:
                text = f.read()
            filename = os.path.basename(filepath)
            send_data = f"UPLOAD@{filename}@{text}"
            client.send(send_data.encode(FORMAT))
        else:
            print(f"Error: File {filepath} does not exist.")
            return False
    except Exception as e:
        print(f"Error reading file {filepath}: {e}")
        return False
    return True

def handle_login(client, username_input, password):
    """Handle user login."""
    global authenticated, username
    
    send_data = f"LOGIN@{username_input}@{password}"
    cmd, response = send_command(client, send_data)
    
    if cmd == "OK":
        authenticated = True
        username = username_input
        client.password = password  # Store for chunk connections
        print(f"✅ {response}")
        return True
    else:
        print(f"❌ Login failed: {response}")
        return False

def parse_response(data):
    """Parse server response."""
    try:
        parts = data.split("@", 1)
        if len(parts) >= 2:
            return parts[0], parts[1]
        else:
            return parts[0], ""
    except:
        return "ERROR", "Invalid response format"

def main():
    """Main client function."""
    global authenticated, username, client_socket
    
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(ADDR)
        print(f"Connected to server at {SERVER_IP}:{PORT}")
        
        # Receive welcome message
        try:
            data = client_socket.recv(SIZE).decode(FORMAT)
            cmd, msg = parse_response(data)
            if cmd == "OK":
                print(f"Server: {msg}")
            else:
                print(f"Unexpected response: {data}")
        except Exception as e:
            print(f"Error receiving welcome message: {e}")
            return

        print_help()

        while True:
            try:
                user_input = input("> ").strip()
                if not user_input:
                    continue
                    
                data = user_input.split(" ")
                cmd = data[0].upper()

                # Handle LOGIN command specially
                if cmd == "LOGIN":
                    if len(data) < 3:
                        print("Usage: LOGIN <username> <password>")
                        continue
                    username_input, password = data[1], data[2]
                    handle_login(client_socket, username_input, password)
                    continue

                # Check authentication for other commands
                if not authenticated and cmd not in ["HELP", "LOGOUT"]:
                    print("❌ Please login first. Use: LOGIN <username> <password>")
                    print("Available users: admin/admin123, user1/pass123, guest/guest123")
                    continue

                if cmd == "HELP":
                    print_help()
                    continue

                elif cmd == "LOGOUT":
                    if authenticated:
                        cmd_resp, response = send_command(client_socket, "LOGOUT")
                        if cmd_resp == "OK":
                            print(f"Server: {response}")
                    break

                elif cmd == "WHOAMI":
                    cmd_resp, response = send_command(client_socket, "WHOAMI")
                    if cmd_resp == "OK":
                        print(f"👤 {response}")
                    else:
                        print(f"Error: {response}")

                elif cmd == "LIST":
                    cmd_resp, response = send_command(client_socket, "LIST")
                    if cmd_resp == "OK":
                        print(f"📁 Files on server:\n{response}")
                    else:
                        print(f"Error: {response}")

                elif cmd == "FILE_INFO":
                    if len(data) < 2:
                        print("Usage: FILE_INFO <filename>")
                        continue
                    filename = data[1]
                    cmd_resp, response = send_command(client_socket, f"FILE_INFO@{filename}")
                    if cmd_resp == "OK":
                        try:
                            file_info = json.loads(response)
                            print(f"📄 File Information for '{filename}':")
                            print(f"   Size: {file_info['size']} bytes")
                            print(f"   Checksum: {file_info['checksum']}")
                            print(f"   Chunks: {file_info['chunks']}")
                        except json.JSONDecodeError:
                            print(f"File info: {response}")
                    else:
                        print(f"Error: {response}")

                elif cmd == "UPLOAD":
                    if len(data) < 2:
                        print("Usage: UPLOAD <filepath>")
                        continue
                    filepath = data[1]
                    if handle_upload(client_socket, filepath):
                        # Wait for response
                        try:
                            response = client_socket.recv(SIZE).decode(FORMAT)
                            resp_cmd, resp_msg = parse_response(response)
                            if resp_cmd == "OK":
                                print(f"✅ {resp_msg}")
                            else:
                                print(f"❌ {resp_msg}")
                        except Exception as e:
                            print(f"Error receiving upload response: {e}")

                elif cmd == "DOWNLOAD_PARALLEL":
                    if len(data) < 2:
                        print("Usage: DOWNLOAD_PARALLEL <filename> [threads]")
                        continue
                    filename = data[1]
                    num_threads = int(data[2]) if len(data) > 2 else 4
                    
                    if num_threads < 1 or num_threads > 10:
                        print("Number of threads must be between 1 and 10")
                        continue
                    
                    print(f"🚀 Starting parallel download of '{filename}' with {num_threads} threads...")
                    start_time = time.time()
                    
                    if download_file_parallel(filename, num_threads):
                        elapsed_time = time.time() - start_time
                        print(f"⏱️  Download completed in {elapsed_time:.2f} seconds")
                    else:
                        print("❌ Download failed")

                elif cmd == "DELETE":
                    if len(data) < 2:
                        print("Usage: DELETE <filename>")
                        continue
                    filename = data[1]
                    cmd_resp, response = send_command(client_socket, f"DELETE@{filename}")
                    if cmd_resp == "OK":
                        print(f"✅ {response}")
                    else:
                        print(f"❌ {response}")
                    
                else:
                    print(f"Unknown command: {cmd}")
                    print("Type HELP for available commands.")
                    continue

            except KeyboardInterrupt:
                print("\nDisconnecting...")
                try:
                    if authenticated:
                        client_socket.send("LOGOUT".encode(FORMAT))
                except:
                    pass
                break
            except Exception as e:
                print(f"Error: {e}")
                break

    except ConnectionRefusedError:
        print(f"❌ Error: Could not connect to server at {SERVER_IP}:{PORT}")
        print("Make sure the server is running.")
    except Exception as e:
        print(f"Client error: {e}")
    finally:
        try:
            if client_socket:
                client_socket.close()
            print("Disconnected from the server")
        except:
            pass

if __name__ == "__main__":
    main()