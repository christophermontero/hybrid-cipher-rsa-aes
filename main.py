import argparse

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Cipher and decipher texts inputs using hybrid cipher')

	# Declare arguments to pass from console
	parser.add_argument('file', help='Insert the name of file as input')

	args = parser.parse_args()