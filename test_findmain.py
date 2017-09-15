import angr
import tempfile
import os


def find_main(binary, entry, dumplen=100):

	lname = tempfile.mktemp(dir="/tmp/", prefix="dump_bin-")
	cmd = "objdump -d {} > {}".format(binary, lname)
	os.system(cmd)
	disasms = list()
	record = False

	for line in open(lname).read().split('\n'):
		if str(hex(entry))[3:] in line or record:
			record = True

			if 'call' in line:
				break
			disasms.append(line)

	t = disasms.pop()
	return int(t.split('push ')[-1].strip()[1:], 16)

for i in os.listdir('./ti'):
	i = "/workspace/ti/" + i
	p = angr.Project(i)
	entry = p.entry
	print i, hex(find_main(i, entry))
