# ------------------------------------------------------------------------------
# TLSで使用する構造体を表すための基本クラス
# ------------------------------------------------------------------------------

import re
import io # バイトストリーム操作
import textwrap # テキストの折り返しと詰め込み
import shutil # ターミナル幅の取得
from metatype import Type, List, ListMeta
from utils import dig

import dataclasses

# TLSメッセージの構造体を表すためのクラス群
# 使い方：
#
#   import metastruct as meta
#
#   @meta.struct
#   class ClientHello(meta.MetaStruct):
#       legacy_version: ProtocolVersion
#       random: Random
#       legacy_session_id: Opaque(size_t=Uint8)
#       cipher_suites: List(size_t=Uint16, elem_t=CipherSuite)
#       legacy_compression_methods: List(size_t=Uint16, elem_t=Uint8)
#       extensions: List(size_t=Uint16, elem_t=Extension)
#

# --- Struct -------------------------------------------------------------------
# 構造体のデコレータ
def struct(cls):
    for name, elem_t in cls.__annotations__.items():
        if not hasattr(cls, name):
            setattr(cls, name, None)
    return dataclasses.dataclass(repr=False)(cls)

def is_MetaStruct(elem):
    return isinstance(elem, MetaStruct)

def is_List_of_MetaStruct(elem):
    return (isinstance(elem, ListMeta) and
            issubclass(elem.__class__.elem_t, MetaStruct))


# 構造体の抽象クラス
class MetaStruct(Type):

    def __post_init__(self):

        self.set_parent(None)

        # create_emptyメソッドで生成されたとき(全ての要素がNoneのとき)は何もしない
        if all(not getattr(self, name) for name in self.get_struct().keys()):
            return

        for name, field in self.get_struct().items():
            elem = getattr(self, name)

            # デフォルト値がラムダのとき、ラムダを評価した値を格納する
            if callable(field.default) and not isinstance(elem, field.type):
                setattr(self, name, field.default(self))

            # 要素が親インスタンスを参照できるようにする
            if isinstance(elem, Type):
                elem.set_parent(self)

    @classmethod
    def create_empty(cls):
        dictionary = {}
        for name, field in cls.__dataclass_fields__.items():
            dictionary[name] = None
        return cls(**dictionary)

    # 全てのMetaStructは親インスタンスを参照できるようにする。
    def set_parent(self, parent: Type):
        self.parent = parent

    def __bytes__(self):
        f = io.BytesIO()
        for name, field in self.get_struct().items():
            elem = getattr(self, name)
            if elem is None:
                raise Exception('%s.%s is None!' % (self.__class__.__name__, name))
            f.write(bytes(elem))
        return f.getvalue()

    @classmethod
    def from_stream(cls, fs: io.BytesIO, parent=None):
        # デフォルト値などを導出せずにインスタンス化する
        instance = cls.create_empty()
        instance.set_parent(parent) # 子が親インスタンスを参照できるようにする

        for name, field in cls.get_struct().items():
            elem_t = field.type

            if isinstance(elem_t, Select):
                # 型がSelectのときは、既に格納した値から型を決定する
                elem_t = elem_t.select_type_by_switch(instance)

            # バイト列から構造体への変換
            elem = elem_t.from_stream(fs, instance)
            # 値を構造体へ格納
            setattr(instance, name, elem)
        return instance

    # 値をプロパティに直接代入した時に親参照を再設定する処理
    def update(self):
        cls = self.__class__
        # instance = cls.create_empty()
        # instance.set_parent(self.parent)
        for name, field in cls.get_struct().items():
            # それぞれの値の親参照を自身に設定
            elem = getattr(self, name)
            if getattr(elem, 'set_parent', None):
                elem.set_parent(self)
            # 値を構造体へ格納
            # setattr(instance, name, elem)
        # return instance

    @classmethod
    def get_struct(cls):
        return cls.__dataclass_fields__

    def __repr__(self):
        # 出力は次のようにする
        # 1. 各要素を表示するときはプラス(+)記号を加えて、出力幅が70を超えないようにする
        #     + 要素名: 型(値)
        # 2. 要素もMetaStructのときは、内部要素をスペース2つ分だけインデントする
        #     + 要素名: MetaStruct名:
        #       + 要素: 型(値)
        title = "%s:\n" % self.__class__.__name__
        elems = []
        for name, field in self.get_struct().items():
            elem = getattr(self, name)
            content = repr(elem)
            output = '%s: %s' % (name, content)

            if is_MetaStruct(elem) or is_List_of_MetaStruct(elem):
                # 要素のMetaStructは出力が複数行になるので、その要素をインデントさせる
                output = textwrap.indent(output, prefix="  ").strip()
            else:
                # その他の要素は出力が1行なので、コンソールの幅を超えないように折返し出力させる
                nest = self.count_ancestors() + 2
                output = '\n  '.join(
                    textwrap.wrap(output, width=shutil.get_terminal_size().columns-(nest*3)))
            elems.append('+ ' + output)
        return title + "\n".join(elems)

    def count_ancestors(self):
        tmp = self.parent
        count = 0
        while tmp is not None:
            tmp = tmp.parent
            count += 1
        return count

    def __len__(self):
        return len(bytes(self))


# --- Select -------------------------------------------------------------------
# 状況に応じて型を選択するためのクラス。
# 例えば、Handshake.msg_type が client_hello と server_hello で、
# 自身や子要素の構造体フィールドの型が変化する場合に使用する。
class Select:
    def __init__(self, switch, cases):
        assert isinstance(switch, str)
        assert isinstance(cases, dict)
        self.switch = switch
        self.cases = cases
        # 引数 switch の構文が正しいか確認する。
        #   自身のプロパティを参照する場合 : "プロパティ名"
        #   親のプロパティを参照する場合 : "親クラス名.プロパティ名"
        #   自身のプロパティから辿って参照する場合 : "self.プロパティ名1.プロパティ名2"
        if not re.match(r'^[a-zA-Z0-9_]+(\.[a-zA-Z_]+)?$|^self\.[a-zA-Z0-9_]+(\.[a-zA-Z_]+)*$', self.switch):
            raise Exception('Select(%s) is invalid syntax!' % self.switch)

    # フィールド .switch の内容を元に、構築中のインスタンスからプロパティを検索し、
    # プロパティの値から導出した型を返す。
    def select_type_by_switch(self, instance):
        if re.match(r'^self\.([^.]+(?:\.[^.]+)*)', self.switch):
            # 条件が「self.プロパティ名.プロパティ名...」のとき
            props = self.switch.split('.')[1:]
            value = dig(instance, *props)
        else:
            if re.match(r'^[^.]+\.[^.]+$', self.switch):
                # 条件が「クラス名.プロパティ名」のとき
                class_name, prop_name = self.switch.split('.', maxsplit=1)
            else:
                # 条件が「プロパティ名」のみ
                class_name, prop_name = instance.__class__.__name__, self.switch
            # インスタンスのクラス名がclass_nameと一致するまで親をさかのぼる
            tmp = instance
            while tmp is not None:
                if tmp.__class__.__name__ == class_name: break
                tmp = tmp.parent
            if tmp is None:
                raise Exception('Not found %s class in ancestors from %s!' % \
                    (class_name, instance.__class__.__name__))
            # 既に格納した値の取得
            value = getattr(tmp, prop_name)
        # 既に格納した値から使用する型を決定する
        ret = self.cases.get(value)
        if ret is None:
            ret = self.cases.get(Otherwise)
        if ret is None:
            raise Exception('Select(%s) cannot map to class in %s!' % \
                (value, instance.__class__.__name__))
        return ret

# Select で条件に当てはまらない場合の default を表すクラス
# Usage:
#     meta.Select('fieldName', cases={
#         HandshakeType.client_hello: ClientHello,
#         meta.Otherwise:             OpaqueLength
#     })
class Otherwise:
    pass
