# Md5-Password
Here is a Python script that implements MD5 encryption and decryption of passwords This Script created By Mr Sabaz ali khan

This script defines two functions:

md5_encrypt(password): This function takes a password as input, encrypts it using the MD5 hashing algorithm, and returns the encrypted password.

md5_decrypt(encrypted_password, password): This function takes an encrypted password and a password as input, encrypts the password using the MD5 hashing algorithm, and compares the encrypted password with the provided encrypted password. It returns True if the password matches, and False otherwise.

The script demonstrates the usage of these functions by encrypting a password and then checking if the decrypted password matches the original password.

Please note that MD5 is a one-way hashing algorithm and is not suitable for password encryption as it is a weak hashing algorithm. It is recommended to use more secure hashing algorithms like SHA-256 or bcrypt for password encryption.
