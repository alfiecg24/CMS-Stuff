import sys
import os

def extract_cms_blob(binary_path):
    with open(binary_path, 'rb') as f:
        data = f.read()
    offset = data.find(b'\xFA\xDE\x0C\xC0')
    if offset != -1:
        length = int.from_bytes(data[offset + 4: offset + 8], 'big')
        cms_blob = data[offset: offset + length]
        output_file = os.path.basename(binary_path) + '_CMSBlob'
        with open(output_file, 'wb') as f:
            f.write(cms_blob)
    else:
        print("CMS blob not found")
        
class CS_BlobIndex:
    def __init__(self, data, offset):
        self.type = int.from_bytes(data[offset:offset+4], 'big')
        self.offset = int.from_bytes(data[offset+4:offset+8], 'big')

class CS_SuperBlob:
    def __init__(self, data):
        self.magic = int.from_bytes(data[0:4], 'big')
        self.length = int.from_bytes(data[4:8], 'big')
        self.count = int.from_bytes(data[8:12], 'big')
        self.index = [CS_BlobIndex(data, 12 + i*8) for i in range(self.count)]

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <binary-file-path>")
        sys.exit(1)
    extract_cms_blob(sys.argv[1])
