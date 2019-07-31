---
title: RFCの読み方
tags:
sidebar: doc_sidebar
permalink: rfc_reading.html
---

## 形式言語

[3. Presentation Language](https://tools.ietf.org/html/rfc8446#section-3)

ここでは、形式言語の読み方について説明します。

データの基本単位は1byteです。バイトの並び順は**ビッグエンディアン**です。
バイト列を数値に変換するときは、C言語で書くと次のようになります。

```
value = (byte[0] << 8*(n-1)) | (byte[1] << 8*(n-2)) | ... | byte[n-1];
```

形式言語の基本的な構文には以下のものがあります。

- `/* コメント */`
- `[[ 任意の文 ]]` ... 省略可能な部分
- `opaque 変数名` ... opaque 型はバイト列を代入するための型 (byte型とほぼ同じ)
- `T T';` ... 既にあるデータ型`T`に新しい名前`T'`をつける

### 数字

8bitの符号なしの数値を uint8 で表し、これを 2, 3, 4, 8個並べたものをそれぞれ uint16, uint24, uint32, uint64 で表します。
上の構文を使うと uint16 から uint64 は次のように定義できます。

```
uint8 uint16[2];
uint8 uint24[3];
uint8 uint32[4];
uint8 uint64[8];
```

ここで定義する全ての値はビッグエンディアン（ネットワークバイトオーダ）です。
つまり、16進数のバイト列 0x01 0x02 0x03 0x04 は16進数の値 0x01020304 と等しく、10進数の 16909060 とも等しいです。

### ベクトル

ベクトルとは同じ種類の要素から成る1次元配列です。
ベクトルの長さ n は定義されている場合もあれば実行時に決まる場合もあります。
どちらの場合にも、ベクトルでは長さ n は要素数ではなくバイト数を表します。

```
opaque Datum[3];   /* 3byteの文字列 */
Datum Data[9];     /* 9byteの文字列 == Datumを3個持つ */
```

ベクトルのサイズが固定長なら `[n]` と書き、可変長なら下限と上限を表す `<最小長..最大長>` で書き表します。

```
T T'[8];         /* 8byte の固定長ベクトル */
T T'<2..2^4-1>;  /* 2byte ~ (2^4-1)byte の可変長ベクトル */
```

### Enum

列挙型は `enum { e1(v1), e2(v2), ... , en(vn) [[, (n)]] } Te;` という形で表されます。
列挙型を定義するときに、要素の最大値 `(n)` が定義される場合もあります。

```
/* 色の定義 */
enum {
  red(3), blue(5), white(7)
} Color;

/* 2byte要求されるが、値としては1,2,4しか取らない */
enum {
  sweet(1), sour(2), bitter(4), (32000)
} Taste;

/* 1から254までは全てmehを表す */
enum {
  sad(0),
  meh(1..254),
  happy(255)
} Mood;
```

列挙型の使い方は2通りあります。どちらで書いても構いません。

```
Color color = Color.blue; /* 厳格な書き方 */
Color color = blue;       /* 明らかなときはこれでよい */
```

### 構造体

構造体とは、既にある複数の値をまとめて格納するための型です。
構造体は次のように宣言します。

```
struct {
    T1 f1;
    T2 f2;
    ...
    Tn fn;
} T;
```

上の例において、2番目の要素を参照するときは `T.f2` と書きます。

### 構造体の定数

構造体を宣言するときに値を代入すると、その値は定数になります。
つまり、定数を代入したフィールドは書き替え不可能になります。

```
struct {
    T1 f1 = 8;  /* T.f1 は常に 8 となる */
    T2 f2;
} T;
```

### 構造体のセレクタ

条件によってフィールドの構造が変わる場合はセレクター (select) を使います。
例えば、メッセージの基本的な内容は同じだけど、クライアント側とサーバ側で送るデータ構造が違うときなどに使います。

```
struct {
    T1 f1;
    T2 f2;
    ....
    Tn fn;
    select (E) {
        case e1: Te1 [[fe1]];
        case e2: Te2 [[fe2]];
        ....
        case en: Ten [[fen]];
    };
} Tv;
```

### 確認の例題

ここまで読めば、形式言語 (Presentation Language) が読めるようになっていると思います。
最後に、以下のサンプルの構造体が読めるか確認してください。

```
enum { apple(0), orange(1) } VariantTag;

struct {
    uint16 number;
    opaque string<0..10>; /* variable length */
} V1;

struct {
    uint32 number;
    opaque string[10];    /* fixed length */
} V2;

struct {
    VariantTag type;
    select (VariantRecord.type) {
        case apple:  V1;
        case orange: V2;
    };
} VariantRecord;
```
