import os
import socket
import sys

SERVER_IP = socket.gethostbyname(socket.gethostname())
PORT = 4466
ADDR = (SERVER_IP, PORT)
SIZE = 1024
FORMAT = "utf-8"

def print_help():
    """Print available commands."""
    print("\nAvailable commands:")
    print("HELP - Show this help message")
    print("LIST - List all files on the server")
    print("UPLOAD <filepath> - Upload a file to the server")
    print("DELETE <filename> - Delete a file from the server")
    print("LOGOUT - Disconnect from the server")
    print()

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
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(ADDR)
        print(f"Connected to server at {SERVER_IP}:{PORT}")
        
        # Receive welcome message
        try:
            data = client.recv(SIZE).decode(FORMAT)
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
                    
                data = user_input.split(" ", 1)  # Split only on first space
                cmd = data[0].upper()

                if cmd == "HELP":
                    client.send("HELP".encode(FORMAT))

                elif cmd == "LOGOUT":
                    client.send("LOGOUT".encode(FORMAT))
                    # Wait for server response
                    try:
                        response = client.recv(SIZE).decode(FORMAT)
                        resp_cmd, resp_msg = parse_response(response)
                        if resp_cmd == "OK":
                            print(f"Server: {resp_msg}")
                    except:
                        pass
                    break

                elif cmd == "LIST":
                    client.send("LIST".encode(FORMAT))

                elif cmd == "UPLOAD":
                    if len(data) < 2:
                        print("Usage: UPLOAD <filepath>")
                        continue
                    filepath = data[1]
                    if not handle_upload(client, filepath):
                        continue

                elif cmd == "DELETE":
                    if len(data) < 2:
                        print("Usage: DELETE <filename>")
                        continue
                    filename = data[1]
                    client.send(f"DELETE@{filename}".encode(FORMAT))
                    
                else:
                    print(f"Unknown command: {cmd}")
                    print("Type HELP for available commands.")
                    continue

                # Receive and process server response
                try:
                    response = client.recv(SIZE).decode(FORMAT)
                    resp_cmd, resp_msg = parse_response(response)
                    
                    if resp_cmd == "OK":
                        print(f"Message from server:\n{resp_msg}")
                    elif resp_cmd == "ERROR":
                        print(f"Error: {resp_msg}")
                    elif resp_cmd == "DISCONNECT":
                        print(f"Server: {resp_msg}")
                        break
                    else:
                        print(f"Server response: {response}")
                        
                except socket.error as e:
                    print(f"Connection error: {e}")
                    break
                except Exception as e:
                    print(f"Error receiving response: {e}")
                    break
                    
            except KeyboardInterrupt:
                print("\nDisconnecting...")
                try:
                    client.send("LOGOUT".encode(FORMAT))
                except:
                    pass
                break
            except Exception as e:
                print(f"Error: {e}")
                break

    except ConnectionRefusedError:
        print(f"Error: Could not connect to server at {SERVER_IP}:{PORT}")
        print("Make sure the server is running.")
    except Exception as e:
        print(f"Client error: {e}")
    finally:
        try:
            client.close()
            print("Disconnected from the server")
        except:
            pass

if __name__ == "__main__":
    main()