
from metatype import Uint16, OpaqueUint8, List

# @meta.struct
# class ALPNProtocol(meta.MetaStruct):
#     next_protocol: OpaqueUint8

ALPNProtocols = List(size_t=Uint16, elem_t=OpaqueUint8)
