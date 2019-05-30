#!/usr/bin/env python2.7

from sys import exit

def read_from_hex_offset(file_stream, hex_offset, bytes_to_read) :
  offset = int(hex_offset, 16)
  file_stream.seek(offset)
  return(file_stream.read(bytes_to_read))

def unpack_stage1(path_to_file) :
  from binascii import hexlify, unhexlify
  from struct import pack

  read_file = open(path_to_file,"rb")
  written_file = open("stage1.bin", "wb")

  ## First XOR key
  xor_key = 0x3cc159bb

  ## Decryption
  start_offset = 0x29f0
  max_offset = 1672
  for i in range(0, max_offset, 4) :
    bytes = hexlify(read_from_hex_offset(read_file, str(hex(start_offset)), 4))
    bytes = hexlify(pack('<L', int(bytes, 16)))
    bytes = (int(bytes, 16) + 0xffffffef) & 0xffffffff ## add eax, FFFFFFEF
    bytes = (bytes ^ xor_key) & 0xffffffff             ## xor eax, esi
    bytes = (bytes + 0xffffffff) & 0xffffffff          ## add eax, FFFFFFFF
    bytes = hexlify(pack('<L', bytes))
    xor_key = int(hexlify(pack('<L', int(bytes, 16))), 16)
    written_file.write(unhexlify(bytes))
    start_offset = start_offset + 4

  written_file.close()
  read_file.close()

def main() :
  unpack_stage1("../../samples/packed_v5.bin")
  
if(__name__ == '__main__') :
  main()
  exit(0)
