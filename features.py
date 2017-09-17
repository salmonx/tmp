import sys
from pwn import p32

class PayloadFeature():

	def __init__(self, payload, eip, read_addr, write_addr, write_content):
		self.payload = payload
		self.feature = ""
		self.eip = p32(eip)
		self.read_addr = p32(read_addr)
		self.write_content = p32(write_content)
		self.write_addr = p32(write_addr)
		self.len = 4

		self.gen_feature()

	def gen_feature(self):
		self.fastfeature() or self.dynamic_check()


	def extract(self, badchars, payload):
		if badchars and payload.count(badchars) == 1:
			idx = payload.index(badchars)
			if len(payload[idx:]) > self.len:
				feature = payload[idx:idx+self.len]
			elif len(payload[:idx]) > self.len:
				feature = payload[idx-self.len:idx]

			if feature != badchars:
				if len(set(feature)) == 4:
					if payload.count(feature) == 1:
						return feature

		temp = list()

		for i in range(len(payload)-4):
			feature = payload[i:i+4]
			if payload.count(feature) == 1:
				if len(set(feature)) == 4:
					if badchars != feature:
						return payload[i:i+4]

		return None
	

	def fastfeature(self):
		for badchars in [self.eip, self.read_addr, self.write_addr, self.write_content]:
			feature = self.extract(badchars, self.payload)
			if feature:
				self.feature = feature
				return True
		return False


	def dynamic_check(self):
		return None
	
		goodindexs = list()
		for i in range(len(payload)-1):
			npayload = payload[:i] + chr(ord((payload[i] + 1) % 255)) + payload[i+1:]


def test():
	eip = 0x78777675
	read_addr = 0x080ea040
	write_addr = 0x080ea040
	write_content = 0x41424344
	payload = "abcde"*10 + "uvwx"

	f = PayloadFeature(payload, eip, read_addr, write_addr,write_content)
	print f.feature



if __name__ == '__main__':
	test()
