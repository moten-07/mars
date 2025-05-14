#!/usr/bin/python

import binascii
import glob
import os
import struct
import sys
import traceback
import zlib

import pyelliptic
import zstandard

import decode_mars_constans as constants


class ZstdDecompressReader:
    def __init__(self, buffer):
        self.buffer = buffer

    def read(self):
        return self.buffer


PRIVATE_KEY = "145aa7717bf9745b91e9569b80bbf1eedaa6cc6cd0e26317d810e35710f44cf8"
PUBLIC_KEY = "572d1e2710ae5fbca54c76a382fdd44050b3a675cb2bf39feebe85ef63d947aff0fa4943f1112e8b6af34bebebbaefa1a0aae055d9259b89a1858f7cc9af9df1"


def tea_decipher(v, k):
    op = 0xffffffff
    v0, v1 = struct.unpack('=LL', v[0:8])
    k1, k2, k3, k4 = struct.unpack('=LLLL', k[0:16])
    delta = 0x9E3779B9
    s = (delta << 4) & op
    for i in range(16):
        v1 = (v1 - (((v0 << 4) + k3) ^ (v0 + s) ^ ((v0 >> 5) + k4))) & op
        v0 = (v0 - (((v1 << 4) + k1) ^ (v1 + s) ^ ((v1 >> 5) + k2))) & op
        s = (s - delta) & op
    return struct.pack('=LL', v0, v1)


def tea_decrypt(v, k):
    num = len(v) // 8 * 8
    ret = b''
    for i in range(0, num, 8):
        x = tea_decipher(v[i:i + 8], k)
        ret += x

    ret += v[num:]
    return ret


def is_good_log_buffer(_buffer, _offset, count):
    if _offset == len(_buffer): return True, ''

    magic_start = _buffer[_offset]
    if constants.MAGIC_NO_COMPRESS_START == magic_start or constants.MAGIC_COMPRESS_START == magic_start or constants.MAGIC_COMPRESS_START1 == magic_start:
        crypt_key_len = 4
    elif constants.MAGIC_COMPRESS_START2 == magic_start or constants.MAGIC_NO_COMPRESS_START1 == magic_start or constants.MAGIC_NO_COMPRESS_NO_CRYPT_START == magic_start or constants.MAGIC_COMPRESS_NO_CRYPT_START == magic_start \
            or constants.MAGIC_SYNC_ZSTD_START == magic_start or constants.MAGIC_SYNC_NO_CRYPT_ZSTD_START == magic_start or constants.MAGIC_ASYNC_ZSTD_START == magic_start or constants.MAGIC_ASYNC_NO_CRYPT_ZSTD_START == magic_start:
        crypt_key_len = 64
    else:
        return False, '_buffer[%d]:%d != MAGIC_NUM_START' % (_offset, _buffer[_offset])

    header_len = 1 + 2 + 1 + 1 + 4 + crypt_key_len

    if _offset + header_len + 1 + 1 > len(_buffer): return (False,
                                                            'offset:%d > len(buffer):%d' % (_offset, len(_buffer)))
    length = struct.unpack_from("I", memoryview(_buffer)[
                                     _offset + header_len - 4 - crypt_key_len:_offset + header_len - crypt_key_len])[0]
    if _offset + header_len + length + 1 > len(_buffer):
        return (False,
                'log length:%d, end pos %d > len(buffer):%d' % (length,
                                                                _offset + header_len + length + 1,
                                                                len(_buffer)))
    if constants.MAGIC_END != _buffer[_offset + header_len + length]: return (False,
                                                                              'log length:%d, buffer[%d]:%d != MAGIC_END' % (
                                                                                  length, _offset + header_len + length,
                                                                                  _buffer[
                                                                                      _offset + header_len + length]))

    if 1 >= count:
        return True, ''
    else:
        return is_good_log_buffer(_buffer, _offset + header_len + length + 1, count - 1)


def get_log_start_pos(_buffer, _count):
    offset = 0
    while True:
        if offset >= len(_buffer): break

        if constants.MAGIC_NO_COMPRESS_START == _buffer[offset] or constants.MAGIC_NO_COMPRESS_START1 == _buffer[
            offset] or constants.MAGIC_COMPRESS_START == _buffer[offset] or constants.MAGIC_COMPRESS_START1 == _buffer[
            offset] or constants.MAGIC_COMPRESS_START2 == _buffer[offset] or constants.MAGIC_COMPRESS_NO_CRYPT_START == \
                _buffer[
                    offset] or constants.MAGIC_NO_COMPRESS_NO_CRYPT_START == _buffer[offset] \
                or constants.MAGIC_SYNC_ZSTD_START == _buffer[offset] or constants.MAGIC_SYNC_NO_CRYPT_ZSTD_START == \
                _buffer[
                    offset] or constants.MAGIC_ASYNC_ZSTD_START == _buffer[
            offset] or constants.MAGIC_ASYNC_NO_CRYPT_ZSTD_START == _buffer[offset]:
            if is_good_log_buffer(_buffer, offset, _count)[0]: return offset
        offset += 1

    return -1


def decode_buffer(_buffer, _offset, _outbuffer):
    if _offset >= len(_buffer): return -1
    # if _offset + 1 + 4 + 1 + 1 > len(_buffer): return -1
    ret = is_good_log_buffer(_buffer, _offset, 1)
    if not ret[0]:
        fixpos = get_log_start_pos(_buffer[_offset:], 1)
        if -1 == fixpos:
            return -1
        else:
            _outbuffer.extend(
                b"[F]decode_log_file.py decode error len=%d, result:%s \n" % (fixpos, ret[1].encode('utf-8')))
            _offset += fixpos

    magic_start = _buffer[_offset]
    if constants.MAGIC_NO_COMPRESS_START == magic_start or constants.MAGIC_COMPRESS_START == magic_start or constants.MAGIC_COMPRESS_START1 == magic_start:
        crypt_key_len = 4
    elif constants.MAGIC_COMPRESS_START2 == magic_start or constants.MAGIC_NO_COMPRESS_START1 == magic_start or constants.MAGIC_NO_COMPRESS_NO_CRYPT_START == magic_start or constants.MAGIC_COMPRESS_NO_CRYPT_START == magic_start \
            or constants.MAGIC_SYNC_ZSTD_START == magic_start or constants.MAGIC_SYNC_NO_CRYPT_ZSTD_START == magic_start or constants.MAGIC_ASYNC_ZSTD_START == magic_start or constants.MAGIC_ASYNC_NO_CRYPT_ZSTD_START == magic_start:
        crypt_key_len = 64
    else:
        _outbuffer.extend(b'in DecodeBuffer _buffer[%d]:%d != MAGIC_NUM_START' % (_offset, magic_start))
        return -1

    header_len = 1 + 2 + 1 + 1 + 4 + crypt_key_len
    length = struct.unpack_from("I", memoryview(_buffer)[
                                     _offset + header_len - 4 - crypt_key_len:_offset + header_len - crypt_key_len])[0]
    tmpbuffer = bytearray(length)

    seq = struct.unpack_from("H", memoryview(_buffer)[
                                  _offset + header_len - 4 - crypt_key_len - 2 - 2:_offset + header_len - 4 - crypt_key_len - 2])[
        0]
    global last_seq
    if seq != 0 and seq != 1 and last_seq != 0 and seq != (last_seq + 1):
        _outbuffer.extend(b"[F]decode_log_file.py log seq:%d-%d is missing\n" % (last_seq + 1, seq - 1))

    if seq != 0:
        last_seq = seq

    tmpbuffer[:] = _buffer[_offset + header_len:_offset + header_len + length]

    try:
        if constants.MAGIC_NO_COMPRESS_START1 == _buffer[_offset] or constants.MAGIC_SYNC_ZSTD_START == _buffer[
            _offset]:
            pass

        elif constants.MAGIC_COMPRESS_START2 == _buffer[_offset] or constants.MAGIC_ASYNC_ZSTD_START == _buffer[
            _offset]:
            svr = pyelliptic.ECC(curve='secp256k1')
            client = pyelliptic.ECC(curve='secp256k1')
            client.pubkey_x = str(memoryview(_buffer, _offset + header_len - crypt_key_len, crypt_key_len / 2))
            client.pubkey_y = str(memoryview(_buffer, _offset + header_len - crypt_key_len / 2, crypt_key_len / 2))

            svr.privkey = binascii.unhexlify(PRIVATE_KEY)
            tea_key = svr.get_ecdh_key(client.get_pubkey())

            tmpbuffer = tea_decrypt(tmpbuffer, tea_key)
            # tmpbuffer = tmpbuffer
            if constants.MAGIC_COMPRESS_START2 == _buffer[_offset]:
                decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
                tmpbuffer = decompressor.decompress(bytes(tmpbuffer))
            else:
                decompressor = zstandard.ZstdDecompressor()
                tmpbuffer = next(decompressor.read_from(ZstdDecompressReader(bytes(tmpbuffer)), 100000, 1000000))
        elif constants.MAGIC_ASYNC_NO_CRYPT_ZSTD_START == _buffer[_offset]:
            decompressor = zstandard.ZstdDecompressor()
            tmpbuffer = next(decompressor.read_from(ZstdDecompressReader(bytes(tmpbuffer)), 100000, 1000000))
        elif constants.MAGIC_COMPRESS_START == _buffer[_offset] or constants.MAGIC_COMPRESS_NO_CRYPT_START == _buffer[
            _offset]:
            decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
            tmpbuffer = decompressor.decompress(bytes(tmpbuffer))
        elif constants.MAGIC_COMPRESS_START1 == _buffer[_offset]:
            decompress_data = bytearray()
            while len(tmpbuffer) > 0:
                single_log_len = struct.unpack_from("H", memoryview(tmpbuffer)[0:2])[0]
                decompress_data.extend(tmpbuffer[2:single_log_len + 2])
                tmpbuffer[:] = tmpbuffer[single_log_len + 2:len(tmpbuffer)]

            decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
            tmpbuffer = decompressor.decompress(bytes(decompress_data))

        else:
            pass

            # _outbuffer.extend('seq:%d, hour:%d-%d len:%d decompress:%d\n' %(seq, ord(begin_hour), ord(end_hour), length, len(tmpbuffer)))
    except Exception as e:
        traceback.print_exc()
        _outbuffer.extend(b"[F]decode_log_file.py decompress err, " + str(e).encode('utf-8') + b"\n")
        return _offset + header_len + length + 1

    _outbuffer.extend(tmpbuffer)

    return _offset + header_len + length + 1


def parse_file(_file, _outfile):
    with open(_file, "rb") as fp:
        _buffer = bytearray(os.path.getsize(_file))
        fp.readinto(_buffer)
    startpos = get_log_start_pos(_buffer, 2)
    if -1 == startpos:
        return

    outbuffer = bytearray()

    while True:
        startpos = decode_buffer(_buffer, startpos, outbuffer)
        if -1 == startpos: break;

    if 0 == len(outbuffer): return

    with open(_outfile, "wb") as fpout:
        fpout.write(outbuffer)


def main(args):
    global last_seq

    if 1 == len(args):
        if os.path.isdir(args[0]):
            filelist = glob.glob(args[0] + "/*.xlog")
            for filepath in filelist:
                last_seq = 0
                parse_file(filepath, filepath + ".log")
        else:
            parse_file(args[0], args[0] + ".log")
    elif 2 == len(args):
        parse_file(args[0], args[1])
    else:
        filelist = glob.glob("*.xlog")
        for filepath in filelist:
            last_seq = 0
            parse_file(filepath, filepath + ".log")


if __name__ == "__main__":
    main(sys.argv[1:])
