import hashlib
import re

BLOCK_SIZE=4096

_rb = re.compile(rb".*<reg:register.*?>")
_re = re.compile(rb"</reg:register.*?>.*")
h = hashlib.sha256()
ha = hashlib.sha256()
filename="/home/phil/tmp/dump.xml"
with open(filename, "rb") as fh:
        s = b''
        p = b''
        fl = 0
        for block in iter(lambda: fh.read(BLOCK_SIZE), b''):
                ha.update(block)
                if fl == 0:
                        s += block
                        if _rb.match(s):
                                h.update(_rb.sub(b"", s))
                                fl = 1
                elif fl == 1:
                        s = p + block
                        if _re.search(s):
                                h.update(_re.sub(b"", s))
                                fl = 2 
                        else:
                                h.update(p)
                                p = block
print("H = %s HA = %s\n" % (h.hexdigest(), ha.hexdigest()))
