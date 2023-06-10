
from metatype import Enum, Uint32

class QUICVersions(Enum):
    enum_t = Uint32

    QUICv1 = Uint32(0x00000001)

class HeaderForm():
    SHORT = 0b0
    LONG  = 0b1
