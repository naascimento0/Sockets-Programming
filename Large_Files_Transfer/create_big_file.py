import os
import random
import string

def generate_large_file(filename, size_mb):
    """Generates a text file with the specified size in MB."""
    # Size in bytes (1 MB = 1024 * 1024 bytes)
    size_bytes = size_mb * 1024 * 1024
    
    # Characters to fill the file
    characters = string.ascii_letters + string.digits
    
    # Generate a base line for repetition
    base_line = ''.join(random.choice(characters) for _ in range(100)) + '\n'
    line_size = len(base_line)
    
    with open(filename, 'w') as f:
        bytes_written = 0
        while bytes_written < size_bytes:
            f.write(base_line)
            bytes_written += line_size
    
    # Adjust final size by truncating the file if necessary
    with open(filename, 'r+') as f:
        f.truncate(size_bytes)
    
    print(f"File '{filename}' generated with {size_mb} MB ({os.path.getsize(filename)} bytes).")

if __name__ == "__main__":
    # Configuration
    filename = "input/big_file.txt"
    size_mb = 5  # File size in MB

    generate_large_file(filename, size_mb)