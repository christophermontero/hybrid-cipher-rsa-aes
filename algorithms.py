from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad

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
	def __init__(self, session_key, text_bytes):
		self.session_key = session_key
		self.session_key_cipher = None
		self.text_bytes = text_bytes
		self.iv = None
		self.iv_cipher = None

	def encrypt_message(self):
		cipher_aes = AES.new(self.session_key, AES.MODE_CBC)
		ciphertext = cipher_aes.encrypt(pad(self.text_bytes, AES.block_size))
		self.iv = cipher_aes.iv

		return ciphertext, cipher_aes.iv

rsa = rsa()
keys_gen = rsa.generate_key_pair()

session_key = get_random_bytes(16) # Random user's key 128 bits
print(session_key)

file_utf8 = open("message.txt","r",encoding='utf-8')
text = file_utf8.read()
file_utf8.close()

# The file is being converted to bytes
text_to_bytes = str.encode(text)

encrypt = rsa.encrypt_key(session_key)
decrypt = rsa.decrypt_key(encrypt)

aes = aes_cbc(session_key,text_to_bytes)
print(aes.encrypt_message())
