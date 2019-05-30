#!/usr/bin/env python2.7

from sys import argv, exit

_R_EMOTET_ = """
rule Emotet_Payload {
  strings :
    /*
      0x406860L 33C0                          xor eax, eax
      0x406862L C705A024410010F74000          mov dword ptr [0x4124a0], 0x40f710
      0x40686cL C705A424410010F74000          mov dword ptr [0x4124a4], 0x40f710
      0x406876L A3A8244100                    mov dword ptr [0x4124a8], eax
      0x40687bL A3AC244100                    mov dword ptr [0x4124ac], eax
      0x406880L 390510F74000                  cmp dword ptr [0x40f710], eax
      0x406886L 7422                          je 0x4068aa
      0x406888L EB06                          jmp 0x406890
      0x40688aL 8D9B00000000                  lea ebx, [ebx]
      0x406890L 40                            inc eax
      0x406891L A3A8244100                    mov dword ptr [0x4124a8], eax
      0x406896L 833CC510F7400000              cmp dword ptr [eax*8 + 0x40f710], 0
      0x40689eL 75F0                          jne 0x406890
      0x4068a0L 51                            push ecx
      0x4068a1L E8FAB6FFFF                    call 0x401fa0
      0x4068a6L 83C404                        add esp, 4
      0x4068a9L C3                            ret 
    */
    $emotet_v5 = { 33 C0 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? A3 ?? ?? ?? ?? A3 ?? ?? ?? ?? 39 05 ?? ?? ?? ?? 74 ?? EB ?? 8D 9B ?? ?? ?? ?? 40 A3 ?? ?? ?? ?? 83 3C C5 ?? ?? ?? ?? ?? 75 ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? C3 }

	  /*
      0x405e76L B850E74000                    mov eax, 0x40e750
      0x405e7bL A350144100                    mov dword ptr [0x411450], eax
      0x405e80L A354144100                    mov dword ptr [0x411454], eax
      0x405e85L 33C0                          xor eax, eax
      0x405e87L 21055C144100                  and dword ptr [0x41145c], eax
      0x405e8dL A358144100                    mov dword ptr [0x411458], eax
      0x405e92L 390550E74000                  cmp dword ptr [0x40e750], eax
      0x405e98L 7418                          je 0x405eb2
      0x405e9aL 40                            inc eax
      0x405e9bL A358144100                    mov dword ptr [0x411458], eax
      0x405ea0L 833CC550E7400000              cmp dword ptr [eax*8 + 0x40e750], 0
      0x405ea8L 75F0                          jne 0x405e9a
      0x405eaaL 51                            push ecx
      0x405eabL E83DBFFFFF                    call 0x401ded
      0x405eb0L 59                            pop ecx
      0x405eb1L C3                            ret 
    */
    $emotet_v6 = { B8 ?? ?? ?? ?? A3 ?? ?? ?? ?? A3 ?? ?? ?? ?? 33 C0 21 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? 39 05 ?? ?? ?? ?? 74 ?? 40 A3 ?? ?? ?? ?? 83 3C C5 ?? ?? ?? ?? ?? 75 ?? 51 E8 ?? ?? ?? ?? 59 C3 }

  condition :
    // check for MZ Signature at offset 0
    (uint16(0) == 0x5A4D) and ($emotet_v5 or $emotet_v6)
}
"""

def cli_args() :
  import argparse
  parser   = argparse.ArgumentParser(
    add_help    = False,
    description = "Emotet 2019 - Get Configuration Toolkit"
  )

  optional = parser._action_groups.pop()
  required = parser.add_argument_group("required arguments")

  required.add_argument(
    "--sample", "-s", action = "store",
    help = "Path to sample file to input."
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

def get_config(data, signature, pe) :
  from binascii import hexlify
  from struct import pack

  image_base = int(pe.OPTIONAL_HEADER.ImageBase)
  raw_pointer = int(pe.sections[2].PointerToRawData)        ## section:.data
  va = int(pe.sections[2].VirtualAddress)
  
  if(signature[0].strings[0][1] == "$emotet_v5") :
    pos_to_ip = (int(hexlify(pack("<L", int(hexlify(signature[0].strings[0][2][8:12]), 16))), 16) - image_base) - va + raw_pointer
  elif(signature[0].strings[0][1] == "$emotet_v6") :
    pos_to_ip = (int(hexlify(pack("<L", int(hexlify(signature[0].strings[0][2][1:5]), 16))), 16) - image_base) - va + raw_pointer
  else : return(False)

  print("[+] IP adresses list")
  print("%s" % ("-" * 40))

  ip = -1
  while ip != 0 :
    ip = int(hexlify(read_from_hex_offset(data, str(hex(pos_to_ip)), 4)), 16)
    if ip != 0 :
      print(" 0x%X\t<->\t%s" % (ip, hex_to_ip(ip)))
    pos_to_ip = pos_to_ip + 8
  return(True)

def hex_to_ip(ip) :
  from socket import inet_ntoa
  from struct import pack

  return(inet_ntoa(pack("<L", ip)))

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
    print("emotet:\t\t%s\nsignature:\t%s (at offset)\n" % (signature[0].strings[0][1], hex(signature[0].strings[0][0])[:-1]))
  else : print("emotet:\t\tnot found!\n")
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

  if(len(matches)) != 0 :
    return(matches)
  return(False)

def main() :
  params = cli_args()
  print("Emotet 2019 - Get Configuration Tools\n\t   by mekhalleh [www.pirates.re]\n")

  ## Get image base address, Yara signature and show PE informations:
  print("%s" % ("=" * 40))
  pe, signature = pe_info(params.sample)

  if(not(signature)) : exiting("No known Emotet signature found!", -1)

  ## Read Emotet configuration:
  print("%s" % ("=" * 40))
  read_file = open(params.sample, "rb")
  if(not(get_config(read_file, signature, pe))) :
    exiting("No supported Emotet version!", -1)

  read_file.close()
  pe.close()
  
if(__name__ == '__main__') :
  main()
  exit(0)
