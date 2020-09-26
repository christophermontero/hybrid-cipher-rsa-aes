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

		print(session_key)

		# Encrypt the session key with the public RSA key
		cipher_rsa = PKCS1_OAEP.new(recipent_key)
		key_encrypted = cipher_rsa.encrypt(session_key)

		return key_encrypted

	def decrypt_key(self, key_encrypted):
		recipent_key = RSA.import_key(open("private.pem").read())
		cipher_rsa = PKCS1_OAEP.new(recipent_key)
		key_decrypted = cipher_rsa.decrypt(key_encrypted)

		return key_decrypted

rsa = rsa()
keys_gen = rsa.generate_key_pair()

encrypt = rsa.encrypt_key()
decrypt = rsa.decrypt_key(encrypt)

print("Encrypt " + str(encrypt))
print("Decrypt " + str(decrypt))
