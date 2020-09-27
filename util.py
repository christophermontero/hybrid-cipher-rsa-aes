class convert():
	def __init__(self, filename):
		self.filename = filename
		self.text_to_bytes = None
		
	def to_bytes(self):
		file_utf8 = open(self.filename,"r",encoding='utf-8')
		text = file_utf8.read()
		file_utf8.close()

		# The file is being converted to bytes
		self.text_to_bytes = str.encode(text)

		return self.text_to_bytes
