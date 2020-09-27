from Crypto.Random import get_random_bytes
import argparse

import algorithms as alg # Import all the algorithms to this file
import util

def main(file_name):
	
	# Instance the rsa class
	rsa = alg.rsa()
	keys_gen = rsa.generate_key_pair()
	session_key = get_random_bytes(16) # Random user's key 128 bits

	# Convert file from utf-8 to bytes
	convert = util.convert(file_name)
	text_to_bytes = convert.to_bytes()

	# Encrypt and decrypt the session key
	key_encrypted = rsa.encrypt_key(session_key)
	key_decrypted = rsa.decrypt_key(key_encrypted)

	# Instance the aes_cbc class
	aes = alg.aes_cbc(key_decrypted,text_to_bytes)
	encrypt_message = aes.encrypt_message()
	iv = encrypt_message[1] # Export the initialize vector
	
	# Decrypt the message into the file
	decrypt_message = aes.decrypt_message(iv)
	
	return encrypt_message, decrypt_message

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Cipher and decipher text files using hybrid cipher')

	# Declare arguments to pass from console
	parser.add_argument('file', help='Insert the name of file as input')
	parser.add_argument('-e', "--encrypt", action="store_true", help='Use to encrypt the input file')
	parser.add_argument('-d', "--decrypt", action="store_true", help='Use to decrypt the message')

	args = parser.parse_args()

	if args.encrypt:
		print("Encrypted message: " + str(main(args.file)[0]))
	else:
		print("Decrypted message: " + str(main(args.file)[1]))
