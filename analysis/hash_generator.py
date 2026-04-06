import hashlib

def generate_hashes(file_path):
    hashes = {}
    with open(file_path, "rb") as f:
        data = f.read()
        hashes['md5'] = hashlib.md5(data).hexdigest()
        hashes['sha1'] = hashlib.sha1(data).hexdigest()
        hashes['sha256'] = hashlib.sha256(data).hexdigest()
    return hashes
