#!/usr/bin/env python2.7

from sys import argv, exit

_R_EMOTET_ = """
rule Emotet_Packed {
  strings :
    /*
      0x1749L BAF0374000                    mov edx, 0x4037f0
      0x174eL 29F6                          sub esi, esi
      0x1750L 81F6BB59C13C                  xor esi, 0x3cc159bb
      0x1756L 52                            push edx
      0x1757L B940000000                    mov ecx, 0x40
      0x175cL 51                            push ecx
      0x175dL BA00100000                    mov edx, 0x1000
      0x1762L 52                            push edx
      0x1763L BA88060000                    mov edx, 0x688
      0x1768L 52                            push edx
      0x1769L B900000000                    mov ecx, 0
      0x176eL 51                            push ecx
      0x176fL B9FFFFFFFF                    mov ecx, 0xffffffff
      0x1774L 51                            push ecx
      0x1775L 8D1D322E4000                  lea ebx, [0x402e32]
      0x177bL FF13                          call dword ptr [ebx]
      0x177dL 5A                            pop edx
      0x177eL 83F800                        cmp eax, 0
      0x1781L 0F8480040000                  je 0x1c07
      0x1787L 29DB                          sub ebx, ebx
      0x1789L 4B                            dec ebx
      0x178aL 21C3                          and ebx, eax
      0x178cL 53                            push ebx
      0x178dL 81FF88060000                  cmp edi, 0x688
      0x1793L 7422                          je 0x17b7
      0x1795L 31C0                          xor eax, eax
      0x1797L 2B02                          sub eax, dword ptr [edx]
      0x1799L F7D8                          neg eax
      0x179bL 8D5204                        lea edx, [edx + 4]
      0x179eL 83C0EF                        add eax, -0x11
      0x17a1L 31F0                          xor eax, esi
      0x17a3L 83C0FF                        add eax, -1
      0x17a6L 89C6                          mov esi, eax
      0x17a8L 894300                        mov dword ptr [ebx], eax
      0x17abL 8D5B04                        lea ebx, [ebx + 4]
      0x17aeL 8D7F04                        lea edi, [edi + 4]
      0x17b1L 688D254000                    push 0x40258d
      0x17b6L C3                            ret
    */
    $packer_v5 = { BA ?? ?? ?? ?? 29 F6 81 F6 ?? ?? ?? ?? 52 B9 ?? ?? ?? ?? 51 BA ?? ?? ?? ?? 52 BA ?? ?? ?? ?? 52 B9 ?? ?? ?? ?? 51 B9 ?? ?? ?? ?? 51 8D 1D ?? ?? ?? ?? FF 13 5A 83 F8 ?? 0F 84 ?? ?? ?? ?? 29 DB 4B 21 C3 53 81 FF ?? ?? ?? ?? 74 ?? 31 C0 2B 02 F7 D8 8D 52 ?? 83 C0 ?? 31 F0 83 C0 ?? 89 C6 89 43 ?? 8D 5B ?? 8D 7F ?? 68 ?? ?? ?? ?? C3 }

    /*
      0xda7L 6896240200                    push 0x22496
      0xdacL 810424AADBFDFF                add dword ptr [esp], 0xfffddbaa
      0xdb3L 6856340200                    push 0x23456
      0xdb8L 810424AADBFDFF                add dword ptr [esp], 0xfffddbaa
      0xdbfL 68DE2A0200                    push 0x22ade
      0xdc4L 810424AADBFDFF                add dword ptr [esp], 0xfffddbaa
      0xdcbL 6A00                          push 0
      0xdcdL 8D05883A4000                  lea eax, [0x403a88]
      0xdd3L FF10                          call dword ptr [eax]
      0xdd5L 85C0                          test eax, eax
      0xdd7L 0F849DF8FFFF                  je 0x67a
      0xdddL 29FF                          sub edi, edi
      0xddfL 81EF88060000                  sub edi, 0x688
      0xde5L F7DF                          neg edi
      0xde7L 68D42C4100                    push 0x412cd4
      0xdecL 5A                            pop edx
      0xdedL 8D30                          lea esi, [eax]
      0xdefL BB6D328001                    mov ebx, 0x180326d
      0xdf4L 56                            push esi
      0xdf5L 85FF                          test edi, edi
      0xdf7L 7427                          je 0xe20
      0xdf9L 29C9                          sub ecx, ecx
      0xdfbL 49                            dec ecx
      0xdfcL 230A                          and ecx, dword ptr [edx]
      0xdfeL 83C204                        add edx, 4
      0xe01L 83C1EE                        add ecx, -0x12
      0xe04L 31D9                          xor ecx, ebx
      0xe06L 8D49FF                        lea ecx, [ecx - 1]
      0xe09L 89CB                          mov ebx, ecx
      0xe0bL 894E00                        mov dword ptr [esi], ecx
      0xe0eL 83EF04                        sub edi, 4
      0xe11L 83EEFC                        sub esi, -4
      0xe14L C70578384000F51B4000          mov dword ptr [0x403878], 0x401bf5
      0xe1eL EBD5                          jmp 0xdf5
    */
    $packer_v6 = { 68 ?? ?? ?? ?? 81 04 24 ?? ?? ?? ?? 68 ?? ?? ?? ?? 81 04 24 ?? ?? ?? ?? 68 ?? ?? ?? ?? 81 04 24 ?? ?? ?? ?? 6A ?? 8D 05 ?? ?? ?? ?? FF 10 85 C0 0F 84 ?? ?? ?? ?? 29 FF 81 EF ?? ?? ?? ?? F7 DF 68 ?? ?? ?? ?? 5A 8D 30 BB ?? ?? ?? ?? 56 85 FF 74 ?? 29 C9 49 23 0A 83 C2 ?? 83 C1 ?? 31 D9 8D 49 ?? 89 CB 89 4E ?? 83 EF ?? 83 EE ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? EB ?? }

  condition :
    // check for MZ Signature at offset 0
    (uint16(0) == 0x5A4D) and ($packer_v5 or $packer_v6)
}
"""

def cli_args() :
  import argparse
  parser   = argparse.ArgumentParser(
    add_help    = False,
    description = "Emotet 2019 - Unpacking Payload Toolkit"
  )

  optional = parser._action_groups.pop()
  required = parser.add_argument_group("required arguments")

  required.add_argument(
    "--sample", "-s", action = "store",
    help = "Path to sample file to input."
  )

  required.add_argument(
    "--out-file", "-of", action = "store",
    help = "Path to unpacked file out."
  )

  optional.add_argument(
    "--out-stage1", "-os1", action = "store",
    help = "Path to stage1 file out."
  )

  optional.add_argument(
    "--help", "-h", action = "store_true",
    help = argparse.SUPPRESS
  )

  parser._action_groups.append(optional)
  return(cli_args_helper(parser.parse_args(), parser))

def cli_args_helper(arguments, parser) :
  from os.path import exists as file_exists

  if(not(arguments.help)) :
    if(not(arguments.sample)) :
      exiting("The path to the sample file is empty!", -1)
    else :
      if(not(file_exists(arguments.sample))) :
        exiting("The file < " + arguments.sample + " > doesn't exist!", -1)

    if(not(arguments.out_file)) :
      exiting("The path to the payload output file is empty!", -1)
    else :
      if(file_exists(arguments.out_file)) :
        exiting("The file < " + arguments.out_file + " > already exist!", -1)

    if(arguments.out_stage1) :
      if(file_exists(arguments.out_stage1)) :
        exiting("The file <" + arguments.out_stage1 + "> already exist!", -1)
  
  # Help message and exit.
  if((arguments.help) or (len(argv) <= 1)) :
    parser.print_help()
    exit(0)

  return(arguments)

def convert_bytes(size) :
  for x in ["Bytes", "Kb", "Mb", "Gb", "Tb"] :
    if size < 1024.0 :
      return("%3.1f %s" % (size, x))
    size /= 1024.0

def digest(algorithm, data) :
  if(algorithm == "md5") :
    from hashlib import md5
    return(md5(data).hexdigest())
  elif(algorithm == "sha1") :
    from hashlib import sha1
    return(sha1(data).hexdigest())
  elif(algorithm == "sha256") :
    from hashlib import sha256
    return(sha256(data).hexdigest())

def exiting(message, ret_code) :
  print("[!!] %s\nExiting..." % (message))
  exit(ret_code)

def file_size(path_to_file) :
  from os import stat
  from os.path import isfile

  if(isfile(path_to_file)) :
    file_info = stat(path_to_file)
    return(convert_bytes(file_info.st_size))
  return(0)

def pe_info(path_to_file) :
  from pefile import PE

  pe = PE(path_to_file)

  data = read_file_to_buffer(path_to_file, "rb")
  print("filename:\t%s\nSize:\t\t%s\nArchitecture\t%s\n\nMD5:\t\t%s\nSHA1:\t\t%s\nSHA256:\t\t%s\n" % (
    path_to_file.split('/')[::-1][0],
    file_size(path_to_file),
    hex(pe.FILE_HEADER.Machine),
    digest("md5", data),
    digest("sha1", data),
    digest("sha256", data)
  ))

  signature = run_yara(_R_EMOTET_, data)
  if(signature) :
    print("packer:\t\t%s\nsignature:\t%s (at offset)\n" % (signature[0].strings[0][1], hex(signature[0].strings[0][0])[:-1]))
  else : print("packer:\t\tnot found!\n")
  return((pe, signature))

def read_file_to_buffer(path_to_file, mode) :
  from os.path import isfile

  if(not(isfile(path_to_file))) : return(False)
  try :
    with open(path_to_file, mode) as file_stream :
      file_content = file_stream.read()
  except Exception as Exception_Error :
    print("%s", (Exception_Error))
    return(False)
  return(file_content)

def read_from_hex_offset(file_stream, hex_offset, bytes_to_read) :
  offset = int(hex_offset, 16)
  file_stream.seek(offset)
  return(file_stream.read(bytes_to_read))

def run_yara(rule_code, buffer_to_sample) :
  from yara import compile

  try :
    yar_object = compile(source = rule_code)
    matches = yar_object.match(data = buffer_to_sample)

  except Exception as Exception_Error :
    print("%s", (Exception_Error))
    return(False)

  if(len(matches) != 0) :
    return(matches)
  return(False)

def unpack_v5(data, signature, pe, path_to_payload, path_to_stage1) :
  from binascii import hexlify, unhexlify
  from struct import pack

  image_base = int(pe.OPTIONAL_HEADER.ImageBase)
  raw_pointer = int(pe.sections[1].PointerToRawData)        ## section:.joi
  va = int(pe.sections[1].VirtualAddress)

  ## stage0: get informations for loading stage1.
  print("\n ++ [ parse_stage0 ] ++")
  xor_key = int(hexlify(pack("<L", int(hexlify(signature[0].strings[0][2][9:13]), 16))), 16)
  v1 = int(hexlify(signature[0].strings[0][2][-23:-22]), 16)
  v2 = int(hexlify(signature[0].strings[0][2][-18:-17]), 16)
  at_offset = (int(hexlify(pack("<L", int(hexlify(signature[0].strings[0][2][1:5]), 16))), 16) - image_base) - va + raw_pointer
  max_offset = int(hexlify(pack("<L", int(hexlify(signature[0].strings[0][2][27:31]), 16))), 16)

  print(" xor_key:\t%s\n v1_add:\t%s\n v2_add:\t%s\n at_offset:\t%s\n max_offset:\t%s" % (
    str(hex(xor_key)),
    str(hex(v1)),
    str(hex(v2)),
    str(hex(at_offset)),
    str(hex(max_offset)),
  ))

  ## stage1: get information to retrieve payload.
  start_offset = at_offset

  stage1 = ""
  for i in range(0, max_offset, 4) :
    bytes = hexlify(read_from_hex_offset(data, str(hex(start_offset)), 4))
    bytes = int(hexlify(pack("<L", int(bytes, 16))), 16)
    bytes = xor_with_addition(bytes, xor_key, v1, v2)
    bytes = hexlify(pack("<L", bytes))
    xor_key = int(hexlify(pack("<L", int(bytes, 16))), 16)  
    stage1 = stage1 + unhexlify(bytes)

    start_offset = start_offset + 4

  ## stage1: get informations for loading payload.
  print("\n ++ [ parse_stage1 ] ++")
  xor_key = int(hexlify(pack("<L", int(hexlify(stage1[-284:-280]), 16))), 16)
  v1 = int(hexlify(pack("<L", int(hexlify(stage1[-354:-350]), 16))), 16)
  v2 = int(hexlify(pack(">L", int(hexlify(stage1[-286:-285]), 16))), 16)
  at_offset = int(hexlify(pack("<L", int(hexlify(stage1[-16:-12]), 16))), 16)
  max_offset = int(hexlify(pack("<L", int(hexlify(stage1[-12:-8]), 16))), 16)
  
  print(" xor_key:\t%s\n v1_sub:\t%s\n v2_sub:\t%s\n at_offset:\t%s\n max_offset:\t%s" % (
    str(hex(xor_key)),
    str(hex(v1)),
    str(hex(v2)),
    str(hex(at_offset)),
    str(hex(max_offset)),
  ))

  ## Unpacking payload.
  sub_key = (int(hexlify(pack("<L", int(hexlify(stage1[-4:]), 16))), 16) + v1) & 0xffffffff
  start_offset = at_offset - va + raw_pointer

  payload = ""
  for i in range(0, max_offset, 4) :
    bytes = hexlify(read_from_hex_offset(data, str(hex(start_offset)), 4))
    next_sub_key = int(bytes, 16)
    bytes = int(hexlify(pack("<L", int(bytes, 16))), 16)
    bytes = xor_with_subtraction(bytes, xor_key, sub_key, v2)
    bytes = hexlify(pack("<L", bytes))
    sub_key = int(hexlify(pack("<L", next_sub_key)), 16)
    payload = payload + unhexlify(bytes)

    start_offset = start_offset + 4

  print("%s" % ("-" * 40))
  if(path_to_stage1) : write_file(path_to_stage1, "wb", stage1)
  if(path_to_payload) : write_file(path_to_payload, "wb", payload)

def unpacking(data, signature, pe, path_to_payload, path_to_stage1) :
  print("[+] Start unpacking payload")
  if(signature[0].strings[0][1] == "$packer_v5") :
    unpack_v5(data, signature, pe, path_to_payload, path_to_stage1)
    return(True)
  return(False)

def write_file(path_to_file, mode, data) :
  try :
    with open(path_to_file, mode) as written_file :
      written_file.write(data)
  except IOError :
    return(False)
  print(" writting:\t%s" % (path_to_file))
  return(True)

def xor_with_addition(bytes, xor_key, v1_add, v2_add) :

  v1_add = int("0xffffff" + str(hex(v1_add)).replace("0x", ''), 16)
  v2_add = int("0xffffff" + str(hex(v2_add)).replace("0x", ''), 16)

  bytes = (bytes + v1_add) & 0xffffffff                        ## add eax, FFFFFFEF
  bytes = (bytes ^ xor_key) & 0xffffffff                       ## xor eax, esi
  bytes = (bytes + v2_add) & 0xffffffff                        ## add eax, FFFFFFFF
  return(bytes)

def xor_with_subtraction(bytes, xor_key, v1_sub, v2_sub) :
  bytes = (bytes - v2_sub) & 0xffffffff                        ## sub eax, 7
  bytes = (bytes ^ xor_key) & 0xffffffff                       ## xor eax, 954132AC
  bytes = (bytes - v1_sub) & 0xffffffff                        ## sub eax, edx
  return(bytes)

def main() :
  params = cli_args()
  print("Emotet 2019 - Unpacking Payload Toolkit\n\t  by mekhalleh [www.pirates.re]\n")

  ## Get image base address, Yara signature and show PE informations:
  print("%s" % ("=" * 40))
  pe, signature = pe_info(params.sample)

  if(not(signature)) : exiting("No known packer signature found!", -1)

  ## Unpacking payload:
  print("%s" % ("=" * 40))
  read_file = open(params.sample, "rb")
  if(not(unpacking(read_file, signature, pe, params.out_file, params.out_stage1))) :
    exiting("No supported packer version!", -1)

  read_file.close()
  pe.close()

if(__name__ == '__main__') :
  main()
  exit(0)
