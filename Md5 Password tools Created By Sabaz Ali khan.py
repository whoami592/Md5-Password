import hashlib

def md5_encrypt(password):
    """
    Encrypts a password using MD5 hashing algorithm.
    
    Args:
        password (str): The password to encrypt.
    
    Returns:
        str: The encrypted password.
    """
    # Convert the password to bytes
    password_bytes = password.encode('utf-8')
    
    # Create an MD5 hash object
    md5_hash = hashlib.md5()
    
    # Update the hash object with the password bytes
    md5_hash.update(password_bytes)
    
    # Get the hexadecimal digest of the hash
    encrypted_password = md5_hash.hexdigest()
    
    return encrypted_password

def md5_decrypt(encrypted_password, password):
    """
    Decrypts an encrypted password using MD5 hashing algorithm.
    
    Args:
        encrypted_password (str): The encrypted password.
        password (str): The password to check against.
    
    Returns:
        bool: True if the password matches the encrypted password, False otherwise.
    """
    # Encrypt the provided password
    decrypted_password = md5_encrypt(password)
    
    # Compare the encrypted password with the provided encrypted password
    return decrypted_password == encrypted_password

# Example usage
password = "mysecretpassword"
encrypted_password = md5_encrypt(password)
print("Encrypted password:", encrypted_password)

# Check if the decrypted password matches the original password
is_match = md5_decrypt(encrypted_password, password)
print("Password match:", is_match)