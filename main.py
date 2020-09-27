from Crypto.Random import get_random_bytes
import argparse

import algorithms as alg # Import all the algorithms to this file

def _main(file_name):
	
	# Instance the rsa class
	rsa = alg.rsa()
	keys_gen = rsa.generate_key_pair()
	session_key = get_random_bytes(16) # Random user's key 128 bits

	file_utf8 = open(file_name,"r",encoding='utf-8')
	text = file_utf8.read()
	file_utf8.close()

	# The file is being converted to bytes
	text_to_bytes = str.encode(text)

	# Encrypt and decrypt the session key
	key_encrypted = rsa.encrypt_key(session_key)
	key_decrypted = rsa.decrypt_key(key_encrypted)

	# Instance the aes_cbc class
	aes = alg.aes_cbc(key_decrypted,text_to_bytes)
	encrypt_message = aes.encrypt_message()
	iv = encrypt_message[1] # Export the initialize vector
	
	# Decrypt the message into the file
	decrypt_message = aes.decrypt_message(iv)
	
	return decrypt_message

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Cipher and decipher texts inputs using hybrid cipher')

	# Declare arguments to pass from console
	parser.add_argument('file', help='Insert the name of file as input')

	args = parser.parse_args()
	print(_main(args.file))
