#!/usr/bin/env python2.7

def get_name(pos, candidates) :
  if(candidates[pos] == ',') :
    pos = pos + 1
  else :
    for i in reversed(range(pos)) :
      if(candidates[i] == ',') :
        break
      pos = pos - 1
  
  name = ""
  for i in range(len(candidates)) :
    if(i >= pos) :
      name = name + candidates[i]
      if(candidates[i] == ',') :
        break
  return(name)

def main() :
  # candidates = "rel,tables,glue,impl,texture,related,key,nis,langs,iprop,exec,wrap,matrix,dump,phoenix,ribbon,sorting,pinned,lics,bit,unpack,adt,rep,jobs,acl,title,sound,events,targets,scrn,mheg,lines,prompt,adjust,xian,ser,cycle,redist,its,boxes,dma,small,cloud,flow,guiddef,whole,parent,bears,random,bulk,idebug,viewer,starta,comment,sel,source,hotspot,pnf,portal,sitka,iell,slide,typ,sonic"
  candidates = "not,ripple,svcs,serv,wab,shader,single,without,wcs,define,eap,culture,slide,zip,tmpl,mini,polic,panes,earcon,menus,detect,form,uuidgen,pnp,admin,tuip,avatar,started,dasmrc,alaska,guids,wfp,adam,wgx,lime,indexer,repl,dev,mapi,resw,daf,diag,iss,vsc,turned,neutral,sat,source,enroll,mfidl,idl,based,right,cbs,radar,avg,wordpad,metagen,mouse,iprop,mdmmcd,jersey,thunk,subs"
  
  VolumeInfo = 0xe42f18a6

  name = ""
  for i in range(2) :
    pos = VolumeInfo % len(candidates)
    VolumeInfo = VolumeInfo / len(candidates)
    VolumeInfo = ~VolumeInfo & 0xffffffff
  
    name = name + get_name(pos, candidates).replace(',', '')

  print(name)

if(__name__ == '__main__') :
  main()
  exit(0)
