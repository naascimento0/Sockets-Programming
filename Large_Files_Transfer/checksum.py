import hashlib
import logging

# An MD5 checksum is a 32-character hexadecimal number that is computed on a file. If two files have the same MD5 checksum value, then there is a high probability that the two files are the same.
def calculate_md5(filename):
    """ Calculate the MD5 hash of a file """
    hash_md5 = hashlib.md5()
    try:
        with open(filename, "rb") as f:
            # Read the file in chunks to avoid overloading memory
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    
    except Exception as e:
        logging.error(f"[!] Error calculating MD5: {e}")
        return None