from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad

class rsa():
	def __init__(self):
		self.public_key = None
		self.private_key = None

	def generate_key_pair(self):
		key = RSA.generate(2048)

		# Private key is being generated
		self.private_key = open("private.pem", "wb")
		self.private_key.write(key.export_key())
		self.private_key.close()

		# Public key is being generated
		self.public_key = open("public.pem", "wb")
		self.public_key.write(key.publickey().export_key())
		self.public_key.close()

		return self.private_key, self.public_key

	def encrypt_key(self, session_key):
		recipent_key = RSA.import_key(open("public.pem").read())

		# Encrypt the session key with the public RSA key
		cipher_rsa = PKCS1_OAEP.new(recipent_key)
		key_encrypted = cipher_rsa.encrypt(session_key)

		return key_encrypted

	def decrypt_key(self, key_encrypted):
		recipent_key = RSA.import_key(open("private.pem").read())
		cipher_rsa = PKCS1_OAEP.new(recipent_key)
		key_decrypted = cipher_rsa.decrypt(key_encrypted)

		return key_decrypted

class aes_cbc():
	def __init__(self, key_decrypted, text_bytes):
		self.session_key = key_decrypted
		self.text_bytes = text_bytes
		self.ciphertext = None
		self.iv = None
		self.text_decrypted_utf8 = None

	def encrypt_message(self):
		cipher_aes = AES.new(self.session_key, AES.MODE_CBC)
		self.ciphertext = cipher_aes.encrypt(pad(self.text_bytes, AES.block_size))
		self.iv = cipher_aes.iv

		return self.ciphertext, self.iv

	def decrypt_message(self, iv):
		cipher_aes = AES.new(self.session_key, AES.MODE_CBC, iv)
		self.text_decrypted_utf8 = unpad(cipher_aes.decrypt(self.ciphertext), AES.block_size).decode('utf-8')

		return self.text_decrypted_utf8
