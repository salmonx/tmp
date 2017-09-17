
import functions
import os
import sys

def basename(f):
	return os.path.basename(f)


def getrop(binary):
	path = "/tmp/rop-{}".format(os.path.basename(binary))
	logpath = "/tmp/rop-log-{}".format(os.path.basename(binary))

	if not os.path.isfile(path):
		open(logpath, 'w').write('running')

		import angr, angrop
		p = angr.Project(binary)
		rop = p.analyses.ROP(fast_mode=True)
		rop.set_badbytes([0x00, 0xD])

		try:
			rop.find_gadgets_single_threaded()
			rop.save_gadgets(path)
			open(logpath, 'w').write('done')
		except:
			try:
				rop.save_gadgets(path)
			except:
				open(logpath, 'w').write('error')


if __name__ == '__main__':
	getrop(sys.argv[1])
