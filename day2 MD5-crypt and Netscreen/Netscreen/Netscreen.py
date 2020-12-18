import base64
import binascii
import hashlib

b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def makepass(user, password):
    middle = "Administration Tools"
    s = "%s:%s:%s" % (user, middle, password)
    # print s
    m = hashlib.md5(s).digest()
    narray = []
     

    for i in range(8):
        n1 = ord(m[2*i])
        n2 = ord(m[2*i+1])
        narray.append( (n1<<8 & 0xff00) | (n2 & 0xff) )
    res = ""
    for i in narray:
        p1 = i >> 12 & 0xf
        p2 = i >> 6  & 0x3f
        p3 = i       & 0x3f
        res += b64[p1] + b64[p2] + b64[p3]
    for c, n in  zip("nrcstn", [0, 6, 12, 17, 23, 29]):
        res = res[:n] + c + res[n:]
    print res
    return res
def reversetomd5(knownhash):
    # strip out nrcstn fixed characters
    clean="" 
    for i in [1,2,3,4,5,7,8,9,10,11,13,14,15,16,18,19,20,21,22,24,25,26,27,28]:
        clean+=knownhash[i]
    # print clean
    # create blocks
    block=[]
    for i in range(2,24,3):
        p1 = b64.index(clean[i-2])
        p2 = b64.index(clean[i-1])
        p3 = b64.index(clean[i])
        block.append(p1 << 12 | p2 << 6 | p3)
    print block;
    # split block into half and find out character for each decimal
    md5hash=b''
    for i in block:
        n1 = i >> 8
        n2 = i & 0xff
        md5hash+=bytes([n1])+bytes([n2])
    print md5hash
    # return binascii.hexlify(md5hash).decode()

code = ("nAePB0rfAm+Nc4YO3s0JwPHtRXIHdn")
print reversetomd5(code)
