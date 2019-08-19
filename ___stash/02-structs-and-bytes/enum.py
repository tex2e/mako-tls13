
class Enum:
    # 全てのTLSの定数群はEnumクラスを継承する。
    #
    # このクラスはTLSで使われる定数群に label() と values() というメソッドを追加する。
    # label() は定数から定数名を取得できる。
    #     HandshakeType.label(Uint16(1)) # => 'client_hello'
    # values() は引数値が定数群に含まれているか確認できる。
    #     self.msg_type in HandshakeType.values() # => True or False

    @classmethod
    def label(cls, value):
        return cls.labels()[value]

    @classmethod
    def labels(cls):
        if not hasattr(cls, '__labels'):
            cls.__labels = dict((v,k) for k,v in cls.__dict__.items()
                                      if not k.startswith('_'))
        return cls.__labels

    @classmethod
    def values(cls):
        if not hasattr(cls, '__values'):
            UintN = Uint.get_type(cls._size)
            cls.__values = set(v for k,v in cls.__dict__.items()
                                 if type(v) == UintN)
        return cls.__values
