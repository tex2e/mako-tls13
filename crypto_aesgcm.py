
class AES128GCM():
    key_size = 32
    nonce_size = 12
    tag_size = 16

    def __init__(self, key, nonce):
        self.key = key
        self.nonce = nonce
