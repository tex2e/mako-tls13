
# B.3.1.4.  Supported Groups Extension
# https://tools.ietf.org/html/rfc8446#appendix-B.3.1.4

from metatype import Uint16, List, Enum
import metastruct as meta

# 鍵交換のための群
class NamedGroup(Enum):
    elem_t = Uint16

    # Elliptic Curve Groups (ECDHE)
    #obsolete_RESERVED = Uint16(0x0001)..Uint16(0x0016)
    secp256r1 = Uint16(0x0017)
    secp384r1 = Uint16(0x0018)
    secp521r1 = Uint16(0x0019)
    #obsolete_RESERVED = Uint16(0x001A)..Uint16(0x001C)
    x25519 = Uint16(0x001D)
    x448 = Uint16(0x001E)

    # Finite Field Groups (DHE)
    # https://tools.ietf.org/html/rfc7919#appendix-A
    ffdhe2048 = Uint16(0x0100)
    ffdhe3072 = Uint16(0x0101)
    ffdhe4096 = Uint16(0x0102)
    ffdhe6144 = Uint16(0x0103)
    ffdhe8192 = Uint16(0x0104)

    # Reserved Code Points
    #ffdhe_private_use = Uint16(0x01FC)..Uint16(0x01FF)
    #ecdhe_private_use = Uint16(0xFE00)..Uint16(0xFEFF)
    #obsolete_RESERVED = Uint16(0xFF01)..Uint16(0xFF02)

NamedGroups = List(size_t=Uint16, elem_t=NamedGroup)

@meta.struct
class NamedGroupList(meta.MetaStruct):
    named_group_list: NamedGroups


if __name__ == '__main__':

    import unittest

    class TestUnit(unittest.TestCase):

        def test_namedgrouplist(self):

            ngl = NamedGroupList(named_group_list=NamedGroups([
                NamedGroup.x25519, NamedGroup.secp256r1,
            ]))
            ngl_bytes = bytes.fromhex('0004 001D 0017')

            self.assertEqual(bytes(ngl), ngl_bytes)
            self.assertEqual(NamedGroupList.from_bytes(bytes(ngl)), ngl)

    unittest.main()
