from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

class rsa():
	def __init__(self):
		self.public = none
		self.private = none
		
