from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

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

	def encrypt_key(self):
		recipent_key = RSA.import_key(open("public.pem").read())
		session_key = get_random_bytes(16) # Random user's key 128 bits

		# Encrypt the session key with the public RSA key
		cipher_rsa = PKCS1_OAEP.new(recipent_key)
		key_encrypted = cipher_rsa.encrypt(session_key)

		return key_encrypted

keys = rsa()
keys_gen = keys.key_pair_generates()
print(keys.encrypt_key())
