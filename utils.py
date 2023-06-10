# ------------------------------------------------------------------------------
# Utils Functions
# ------------------------------------------------------------------------------

import binascii

# --- Hex Dump -----------------------------------------------------------------

def hexdump(data: bytes) -> str:
    return '\n'.join(__dumpgen(data))

def __dumpgen(data: bytes) -> str:
    # Generator that produces strings (addr, hexstr, ascii):
    # 00000000: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
    generator = __chunks(data, 16)
    for addr, d in enumerate(generator):
        # address
        line = '%08X: ' % (addr*16)
        # hexstr
        dumpstr = __dump(d)
        line += dumpstr[:8*3]
        if len(d) > 8: # insert separator if needed
            line += ' ' + dumpstr[8*3:]

        # indent
        pad = 2
        if len(d) < 16:
            pad += 3 * (16 - len(d))
        if len(d) <= 8:
            pad += 1
        line += ' ' * pad
        # ascii
        for byte in d:
            # printable ASCII range 0x20 to 0x7E
            line += chr(byte) if 0x20 <= byte <= 0x7E else '.'
        yield line

# list(chunks([1,2,3,4,5,6,7], 3)) #=> [[1, 2, 3], [4, 5, 6], [7]]
def __chunks(seq: list, size: int) -> list:
    d, m = divmod(len(seq), size)
    for i in range(d):
        yield seq[i*size:(i+1)*size]
    if m:
        yield seq[d*size:]

def __dump(binary: bytes, size=2, sep=' ') -> str:
    return sep.join(__chunks(__hexstr(binary).upper(), size))

def __hexstr(binary: bytes) -> str:
    return binascii.hexlify(binary).decode('ascii')


# --- Bytes --------------------------------------------------------------------

def bytexor(b1, b2):
    result = bytearray(b1)
    for i, b in enumerate(b2):
        result[i] ^= b
    return bytes(result)


# --- Object -------------------------------------------------------------------

def dig(obj, *keys, error=True):
    keys = list(keys)
    if isinstance(keys[0], list):
        return dig(obj, *keys[0], error=error)

    if isinstance(obj, dict) and keys[0] in obj or \
       isinstance(obj, list) and keys[0] < len(obj):
        if len(keys) == 1:
            return obj[keys[0]]
        return dig(obj[keys[0]], *keys[1:], error=error)

    if hasattr(obj, keys[0]):
        if len(keys) == 1:
            return getattr(obj, keys[0])
        return dig(getattr(obj, keys[0]), *keys[1:], error=error)

    if error:
        raise KeyError(keys[0])

    return None
