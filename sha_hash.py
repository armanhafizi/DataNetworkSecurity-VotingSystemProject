from Crypto.Hash import SHA256

def sha_hash(msg):
    hash_object = SHA256.new(data=msg)
    return hash_object.hexdigest()