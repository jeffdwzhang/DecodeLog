# This is a sample Python script.
import sys
import glob
import os.path
import zlib
import struct
import traceback

import zstandard as zstd


# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.


MAGIC_SYNC_ZLIB_START = 0x06
MAGIC_SYNC_ZLIB_NO_CRYPT_START = 0x07
MAGIC_ASYNC_ZLIB_START = 0x08
MAGIC_ASYNC_ZLIB_NO_CRYPT_START = 0x09

MAGIC_SYNC_ZSTD_START = 0x0A
MAGIC_SYNC_NO_CRYPT_ZSTD_START = 0x0B
MAGIC_ASYNC_ZSTD_START = 0x0C
MAGIC_ASYNC_NO_CRYPT_ZSTD_START = 0x0D

MAGIC_END = 0x00

lastseq = 0

PRIV_KEY = "145aa7717bf9745b91e9569b80bbf1eedaa6cc6cd0e26317d810e35710f44cf8"
PUB_KEY = "572d1e2710ae5fbca54c76a382fdd44050b3a675cb2bf39feebe85ef63d947aff0fa4943f1112e8b6af34bebebbaefa1a0aae055d9259b89a1858f7cc9af9df1"

def tea_decipher(v, k):
    op = 0xffffffff
    delta = 0x9E3779B9
    v0, v1 = struct.unpack('=LL', v[0:8])
    k1, k2, k3, k4 = struct.unpack('=LLL', k[0:16])
    s = (delta << 4) & op

def tea_decrypt(v, k):
    num = len(v) / 8 * 8
    ret = ''

def isValideStart(magic_start):
    if MAGIC_SYNC_ZLIB_START == magic_start \
            or MAGIC_SYNC_ZLIB_NO_CRYPT_START == magic_start \
            or MAGIC_ASYNC_ZLIB_START == magic_start \
            or MAGIC_ASYNC_ZLIB_NO_CRYPT_START == magic_start \
            or MAGIC_SYNC_ZSTD_START == magic_start \
            or MAGIC_SYNC_NO_CRYPT_ZSTD_START == magic_start \
            or MAGIC_ASYNC_ZSTD_START == magic_start \
            or MAGIC_ASYNC_NO_CRYPT_ZSTD_START == magic_start:
        return True
    else:
        return False

def IsGoodLogBuffer(_buffer, _offset, count):
    if _offset == len(_buffer):
        return (True, '')

    magic_start = _buffer[_offset]
    if isValideStart(magic_start):
        crypt_key_len = 64
    else:
        return False, '_buffer[%d]:%d != MAGIC_NUM_START' % (_offset, _buffer[_offset])

    headerLen = 1 + 2 + 1 + 1 + 4 + crypt_key_len

    if _offset + headerLen + 1 + 1 > len(_buffer):
        return False, 'offset:%d > len(buffer):%d' % (_offset, len(_buffer))

    v = memoryview(_buffer)
    index = _offset + headerLen - 4 - crypt_key_len
    length = struct.unpack_from("I", v[index: index + 4])[0]
    if _offset + headerLen + length + 1 > len(_buffer):
        return (
            False,
            'log length:%d, end pos %d > len(buffer):%d' % (length, _offset + headerLen + length + 1, len(_buffer))
        )
    magic_end = _buffer[_offset + headerLen + length]
    print("offset: ", _offset, "length: ", length , "magic_end: ", magic_end)
    if MAGIC_END != _buffer[_offset + headerLen + length]:
        return (False,
                'log length:%d, buffer[%d]:%d != MAGIC_END' % (length, _offset + headerLen + length, _buffer[_offset + headerLen + length]))

    if (1 >= count):
        return True, ''
    else:
        return IsGoodLogBuffer(_buffer, _offset + headerLen + length + 1, count - 1)


def GetLogStartPos(_buffer, _count):
    offset = 0
    while True:
        if offset >= len(_buffer):
            break
        magic_start = _buffer[offset]
        if isValideStart(magic_start):
            if IsGoodLogBuffer(_buffer, offset, _count)[0]:
                print("GetLogStartPos -> offset:", offset, " magic_start:", magic_start)
                return offset

        offset += 1

    return -1


def DecodeBuffer(_buffer, _offset, _outbuffer):
    if _offset >= len(_buffer):
        return -1
    # if _offset + 1 + 4 + 1 + 1 > len(_buffer): return -1
    ret = IsGoodLogBuffer(_buffer, _offset, 1)
    if not ret[0]:
        fixpos = GetLogStartPos(_buffer[_offset:], 1)
        if -1 == fixpos:
            return -1
        else:
            _outbuffer.extend("[F]decode_log_file.py decode error len=%d, result:%s \n" % (fixpos, ret[1]))
            _offset += fixpos

    magic_start = _buffer[_offset]
    print('magic_start:', magic_start)

    if isValideStart(magic_start):
        crypt_key_len = 64
    else:
        _outbuffer.extend('in DecodeBuffer _buffer[%d]:%d != MAGIC_NUM_START' % (_offset, magic_start))
        return -1

    headerLen = 1 + 2 + 1 + 1 + 4 + crypt_key_len

    v = memoryview(_buffer)
    index = _offset + headerLen - 4 - crypt_key_len
    length = struct.unpack_from("I", v[index: index + 4])[0]
    print("DecodeBuffer -> index:", index, "log length:", length)
    tmpbuffer = bytearray(length)

    index = _offset + headerLen - 4 - crypt_key_len - 2 - 2
    seq = struct.unpack_from("H", v[index: index + 2])[0]
    index = _offset + headerLen - 4 - crypt_key_len - 1 - 1
    begin_hour = struct.unpack_from("c", v[index: index + 1])[0]
    index = _offset + headerLen - 4 - crypt_key_len - 1
    end_hour = struct.unpack_from("c", v[index: index + 1])[0]

    print(seq, begin_hour, end_hour, end=' ')
    print('\n')

    global lastseq
    if seq != 0 and seq != 1 and lastseq != 0 and seq != (lastseq + 1):
        _outbuffer.extend("[F]decode_log_file.py log seq:%d-%d is missing\n" % (lastseq + 1, seq - 1))

    if seq != 0:
        lastseq = seq

    tmpbuffer[:] = _buffer[_offset + headerLen : _offset + headerLen + length]

    try:
        if MAGIC_SYNC_ZLIB_START == _buffer[_offset] \
                or MAGIC_SYNC_ZLIB_NO_CRYPT_START == _buffer[_offset] \
                or MAGIC_SYNC_ZSTD_START == _buffer[_offset] \
                or MAGIC_SYNC_NO_CRYPT_ZSTD_START == _buffer[_offset]:
            # 同步模式下，log暂时未压缩，因此无需解压缩
            pass
        elif MAGIC_ASYNC_ZLIB_START == _buffer[_offset]:
            decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
            tmpbuffer = decompressor.decompress(tmpbuffer)
        elif MAGIC_ASYNC_ZSTD_START == _buffer[_offset]:
            tmpbuffer = zstd.decompress(tmpbuffer, 1000000)
        elif MAGIC_ASYNC_NO_CRYPT_ZSTD_START == _buffer[_offset]:
            tmpbuffer = zstd.decompress(tmpbuffer, 1000000)
        elif  MAGIC_ASYNC_ZLIB_NO_CRYPT_START == _buffer[_offset]:
            decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
            tmpbuffer = decompressor.decompress(tmpbuffer)

        else:
            pass

            # _outbuffer.extend('seq:%d, hour:%d-%d len:%d decompress:%d\n' %(seq, ord(begin_hour), ord(end_hour), length, len(tmpbuffer)))
    except Exception as e:
        traceback.print_exc()
        _outbuffer.extend("[F]decode_log_file.py decompress err, " + str(e) + "\n")
        return _offset + headerLen + length + 1

    _outbuffer.extend(tmpbuffer)

    # 返回下一句log的起始
    return _offset + headerLen + length + 1


def ParseFile(_file, _outfile):
    print("ParseFile -> file: " + _file)
    fp = open(_file, "rb")
    _buffer = bytearray(os.path.getsize(_file))
    fp.readinto(_buffer)
    fp.close()

    startpos = GetLogStartPos(_buffer, 2)
    if -1 == startpos:
        return

    outbuffer = bytearray()
    while True:
        startpos = DecodeBuffer(_buffer, startpos, outbuffer)
        if -1 == startpos:
            break

    if 0 == len(outbuffer):
        return

    fpout = open(_outfile, "wb")
    fpout.write(outbuffer)
    fpout.close()


def main(args):
    global lastseq
    print("main: args len:" + str(len(args)))
    if 1 == len(args):
        if os.path.isdir(args[0]):
            filelist = glob.glob(args[0] + "/*.alog")
            for filepath in filelist:
                lastseq = 0
                ParseFile(filepath, filepath + ".log")
        else:
            ParseFile(args[0], args[0] + ".log")
    elif 2 == len(args):
        ParseFile(args[0], args[1])
    else:
        filelist = glob.glob("*.xlog")
        for filepath in filelist:
            lastseq = 0
            ParseFile(filepath, filepath + ".log")


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    args = ["logs/"]
    main(args)

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
