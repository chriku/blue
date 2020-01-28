local ffi=require"ffi"
local bit=require"bit"
ffi.cdef[[
int crypto_scalarmult_curve25519(unsigned char *q, const unsigned char *n,
                                 const unsigned char *p)
]]
local sodium=ffi.load("/usr/lib/x86_64-linux-gnu/libsodium.so.23")
local curve={}
local function impl(secret,basepoint)
  local output=ffi.new("unsigned char[32]")
  local secret=ffi.cast("unsigned char*",secret)
  local bp=ffi.new("unsigned char[32]")
  ffi.copy(bp,basepoint,32)
  bp[31]=bit.band(bp[31],0x7f)
  assert(sodium.crypto_scalarmult_curve25519(output,secret,bp)==0)
  return ffi.string(output,32)
end
local function unhex(a) local ret=""
  for b in a:gmatch("[0-9A-F][0-9A-F]") do
    ret=ret..string.char(tonumber(b,16))
  end
  return ret
end
function curve.gen_key()
  local key=string.rep(string.char(10),32)
  local k0=string.byte(key,1)
  local k31=string.byte(key,32)
  key=string.char(bit.band(k0,248))..key:sub(2,31)..string.char(bit.bor(64,bit.band(127,k31)))
--key=unhex("B0 5F 13 56 60 78 EC FE D7 A5 44 71 1E 9E B5 72 24 BA 38 35 B1 94 FB 1E 56 CF 7C A6 03 99 7C 5A")
  local pubkey=impl(key,string.char(9)..string.rep(string.char(0),31))
  --local pubkey=impl(key,string.rep(string.char(0),31)..string.char(9))
  return pubkey,key
end
function curve.handshake(skey,pkey)
  print(skey:len(),pkey:len())
  assert(skey:len()==32)
  assert(pkey:len()==32)
  return impl(skey,pkey)
end
return curve
