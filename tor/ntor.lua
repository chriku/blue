local struct = require "blue.struct"
local curve = require "blue.tor.curve"
local rsa = require "blue.tor.rsa"
local hmac = require "blue.tor.hmac"
local rfc5869=require"blue.tor.rfc5869"
local base64 = require "blue.base64"
local HANDSHAKE_TYPE_NTOR = 2
--[[
Router ID DA 8D 76 F5 F5 81 96 93 B5 C9 6F 49 9B A1 9F 74 04 01 47 69
Pubkey B E0 52 F2 ED 8E 5E 29 B6 8B 9F B8 C5 3D 06 E7 1C 7E 6E 33 6D 14 4F 93 60 1B 81 FD 0A E1 3D EF 30
Privkey x A8 3B 9B 6E 5A B4 A8 A7 86 68 C2 1F 1B 36 FB E7 01 F6 96 71 AD 8C 48 7D 26 E4 C6 6B 52 99 B3 55
Pubkey X A0 FF 2E 0D 28 F0 B1 85 89 80 59 67 28 CF 98 B1 A6 E5 78 82 DA 96 AC 15 69 45 90 1C F3 D9 B0 35
Jan 28 23:24:27.000 [notice] Bootstrapped 90% (ap_handshake_done): Handshake finished with a relay to build circuits
Jan 28 23:24:27.000 [notice] Bootstrapped 95% (circuit_create): Establishing a Tor circuit
Router ID E9 59 55 CD 7A B0 12 DE 77 07 11 87 8F 14 7C 78 4F C1 3D 37
Pubkey B 74 1C B6 63 E6 C3 9B 0C 68 42 83 3F C6 44 53 04 0A 47 D4 FB C9 54 7F 8B CF E6 DC 79 F9 EB CB 02
Privkey x D8 89 00 11 20 88 E0 B8 D2 A4 CD C5 87 02 65 27 00 25 0A 8C 96 E2 E0 E2 D7 CE 1E 44 E5 B0 EF 67
Pubkey X E0 F9 F0 94 3B 01 5A 47 61 2D BC 4F 68 D5 F0 C8 BC 8B 88 21 3E 9E 2B 2C BB 87 24 F9 A6 E1 11 57
Handshake Reply 
C0 F0 D9 8D 30 DA 82 72 E0 87 72 62 A9 BD 40 BC 26 D0 51 04 B4 A6 C9 A3 20 7F 73 5A 8B 7B C6 0A 84 B4 9D EC 
8D 37 20 97 BF 38 6A AB 3D 44 2E E7 3A 14 AD 45 81 42 47 65 14 B0 DB CA 7E 9F DC 08
Secret Input 76 CB A4 CE 6E B0 FB DF C6 BE 97 80 80 8E FB 3A 65 66 F1 3E 35 8D 4E 38 CC 9B 00 CC 7D 72 69 7B DC 4A 57 B8 0F 3B 84 E0 F5 24 2A B0 44 25 D4 8B 60 1A 77 14 C0 06 67 E5 E4 75 D6 00 43 C8 C6 30 DA 8D 76 F5 F5 81 96 93 B5 C9 6F 49 9B A1 9F 74 04 01 47 69 E0 52 F2 ED 8E 5E 29 B6 8B 9F B8 C5 3D 06 E7 1C 7E 6E 33 6D 14 4F 93 60 1B 81 FD 0A E1 3D EF 30 A0 FF 2E 0D 28 F0 B1 85 89 80 59 67 28 CF 98 B1 A6 E5 78 82 DA 96 AC 15 69 45 90 1C F3 D9 B0 35 C0 F0 D9 8D 30 DA 82 72 E0 87 72 62 A9 BD 40 BC 26 D0 51 04 B4 A6 C9 A3 20 7F 73 5A 8B 7B C6 0A 6E 74 6F 72 2D 63 75 72 76 65 32 35 35 31 39 2D 73 68 61 32 35 36 2D 31
Verify DF 21 22 66 EE 40 C0 3F B8 A0 B5 A6 C1 57 11 A6 80 29 E4 37 FB E1 4F D6 9A 1A D8 3B 86 18 96 09
Auth Input DF 21 22 66 EE 40 C0 3F B8 A0 B5 A6 C1 57 11 A6 80 29 E4 37 FB E1 4F D6 9A 1A D8 3B 86 18 96 09 DA 8D 76 F5 F5 81 96 93 B5 C9 6F 49 9B A1 9F 74 04 01 47 69 E0 52 F2 ED 8E 5E 29 B6 8B 9F B8 C5 3D 06 E7 1C 7E 6E 33 6D 14 4F 93 60 1B 81 FD 0A E1 3D EF 30 C0 F0 D9 8D 30 DA 82 72 E0 87 72 62 A9 BD 40 BC 26 D0 51 04 B4 A6 C9 A3 20 7F 73 5A 8B 7B C6 0A A0 FF 2E 0D 28 F0 B1 85 89 80 59 67 28 CF 98 B1 A6 E5 78 82 DA 96 AC 15 69 45 90 1C F3 D9 B0 35 6E 74 6F 72 2D 63 75 72 76 65 32 35 35 31 39 2D 73 68 61 32 35 36 2D 31 53 65 72 76 65 72
Auth 84 B4 9D EC 8D 37 20 97 BF 38 6A AB 3D 44 2E E7 3A 14 AD 45 81 42 47 65 14 B0 DB CA 7E 9F DC 08 70 8A 00 00 00 00 00 00 00 00 00 75 26 57 84 A7 70 8A 78 75 11 3B 4F 56 00 00 78 75 11 3B 4F 56 00 00 26 8D 1E 5E FE 7F 00 00 48 00 00 00 00 00 00 00 90 8C 1E 5E FE 7F 00 00 90 75 11 3B 4F 56 00 00 80 9F 7D 3B 4F 56 00 00 ED C1 CD 39 4F 56 00 00 5C 00 00 00 00 00 00 00 88 8C 1E 5E FE 7F 00 00 00 00 00 00 00 00 00 00 00 75 26 57 84 A7 70 8A 00 00 00 00 00 00 00 00 22 8D 1E 5E FE 7F 00 00 70 75 11 3B 4F 56 00 00 70 FE 7C 3B 4F 56 00 00
Secret Input 76 CB A4 CE 6E B0 FB DF C6 BE 97 80 80 8E FB 3A 65 66 F1 3E 35 8D 4E 38 CC 9B 00 CC 7D 72 69 7B DC 4A 57 B8 0F 3B 84 E0 F5 24 2A B0 44 25 D4 8B 60 1A 77 14 C0 06 67 E5 E4 75 D6 00 43 C8 C6 30 DA 8D 76 F5 F5 81 96 93 B5 C9 6F 49 9B A1 9F 74 04 01 47 69 E0 52 F2 ED 8E 5E 29 B6 8B 9F B8 C5 3D 06 E7 1C 7E 6E 33 6D 14 4F 93 60 1B 81 FD 0A E1 3D EF 30 A0 FF 2E 0D 28 F0 B1 85 89 80 59 67 28 CF 98 B1 A6 E5 78 82 DA 96 AC 15 69 45 90 1C F3 D9 B0 35 C0 F0 D9 8D 30 DA 82 72 E0 87 72 62 A9 BD 40 BC 26 D0 51 04 B4 A6 C9 A3 20 7F 73 5A 8B 7B C6 0A 6E 74 6F 72 2D 63 75 72 76 65 32 35 35 31 39 2D 73 68 61 32 35 36 2D 31
T_KEY 6E 74 6F 72 2D 63 75 72 76 65 32 35 35 31 39 2D 73 68 61 32 35 36 2D 31 3A 6B 65 79 5F 65 78 74 72 61 63 74
M_EXPAND 6E 74 6F 72 2D 63 75 72 76 65 32 35 35 31 39 2D 73 68 61 32 35 36 2D 31 3A 6B 65 79 5F 65 78 70 61 6E 64
KEY_OUT C8 0C 42 28 32 3E 91 30 8F 27 10 D7 01 E0 A4 20 83 49 81 EB D4 EF 0F C6 68 24 CA 33 26 13 87 58 7D D3 93 A0 E7 F1 64 8E EC 6F 64 05 43 19 CD 7C 35 B0 55 F9 CD 9B 3F 49 B9 D7 60 41 FD 3A 6C EF 8F 95 5A D9 01 E8 EE 56 F4 4E E6 ED 31 96 FC 14 EB 6C 83 D4 9C 25 10 F5 97 5B 1A 73
RELAY OUTBOUND A 0D 00 00 54 7B 00 00 00 00 00 00 00 00 00 00 B6 6D 84 70 7E 6F BA C4 58 F2 B7 DD 45 05 B8 46 71 1B 49 E1 0E 20 23 87 E5 FA 82 99 A6 22 D9 8E 28 46 C1 2A B1 75 8C F6 67 35 E3 79 F2 31 F0 8A F6 EB FE 72 EE EC 46 8E C2 06 F3 B2 C3 66 B8 02 40 F1 AE 83 13 E2 99 AC EB A8 DE 1F 51 63 38 93 47 00 A4 1A 02 80 E2 86 22 3B F4 1D 2C BA A8 AA 82 85 59 BA 3E DD E2 90 83 11 EC F3 8C 22 5F 89 85 0D F7 29 92 4B 3E 1B 26 0D 35 21 58 27 CE E3 69 2B 4B 0A F6 14 AE 94 42 FA 7A E0 50 26 EC 99 D2 CD B2 A4 EB 0D 8A 86 6C 7E C2 5E 86 D1 7F F9 32 D4 BF 11 FB F0 2E 3A A5 87 C4 18 5E 22 DA 70 B0 FB CE FE 1D 41 51 9C 46 86 ED 55 A5 68 1D 7E 36 E2 72 CE 38 71 17 CC 8E E4 D5 1A 27 B8 99 A2 47 38 23 42 0A 03 A1 B4 45 98 3D C3 BD 50 8A 10 A4 CF DA 46 28 AE 3B D1 EF 2E 13 14 E2 C2 33 01 97 B6 1E 5A 44 0C 03 BC 15 3E 5F D1 2B 9F 1C 92 8A 77 11 0A 83 12 6A CF 4B 47 0A C7 33 A7 A0 60 02 B5 77 75 8A 61 32 0A 4C 94 99 D8 94 22 A2 F9 BF 94 28 B4 FC 6D A7 F1 8E 77 A8 0F EB 7D B1 45 E9 D9 89 EB F5 19 0A 2A 84 2B B7 94 70 21 DD FF FE C0 C6 AB A0 19 CA CA DD F6 92 94 62 B5 4A 74 26 DA C0 54 62 31 99 E4 1D D2 05 3B 60 97 33 47 3D 91 CA E6 D4 A9 46 67 E7 ED 7A 44 C9 E4 59 B2 D8 25 A2 5D 0F 29 9E 1C A1 29 CF C6 05 BA 26 5A A3 F0 3F 61 CE 2E 4E 4D 78 62 FA F1 42 46 12 32 63 A0 8F 94 3F 8E FB E7 DA C1 9B 1E DB 57 D1 64 01 A3 13 29 43 F1 28 47 E9 53 B7 FC DF AE CA 63 8F 47 9A 76 F3 4F 3A 84 1A 70 1C 02 89 CE D4 A5 C2 4E 0A 14 E0 83 B1 AF 9F E4 AD FC 82 58 18 37 3E 16 70 A8 F8 98 6E 2B 54 B7 34 2B 17 86 AA 04 2A 6F 9A 01 2F A3 38 FC FA 6C 84 D8 9C A4
RELAY OUTBOUND B BF 85 08 02 0D 7E E7 1A 52 51 B0 98 76 3C 53 18 7D 0E 51 7F CE 46 0D 90 26 AC 5A 54 05 64 BA 9A 04 11 7C 8C DB 8D 33 D1 37 9E 64 09 65 54 42 4E C0 09 01 7A B4 28 03 4E 82 B6 04 04 E6 39 CF 6A DB ED A9 F5 AC FB FF 6A 22 D9 15 E4 A1 24 43 B5 27 32 3C F3 E7 AF BB C3 6F F8 BD B9 1B 04 0F 99 D3 FD 87 EA 96 75 61 F0 6A 4B 68 A9 0C D1 46 D2 95 E2 3F AE 7B 8F DE A5 3D 4D 10 7D 96 C0 75 74 8A 4F BD CC 18 63 3C FD 05 82 B2 72 00 D5 CC FB 8F 7B 68 D1 3C F4 27 18 62 91 80 AD CF D2 EC CC E2 17 04 7A 5C F4 59 0E CC 33 D9 C7 04 18 67 3B B5 4A 07 AE 0B 71 64 B5 3C 27 51 F4 F5 D9 A7 8F AE 14 C9 30 96 EE C8 0C 45 B1 80 8B 7A 07 0F 1C 78 59 29 E3 3D 0B 71 36 9B 4B 8D E1 89 78 93 A9 06 CC 2F 48 82 BB AD 90 F3 E3 02 BE 5E 1A C0 F8 61 9E 2E 20 87 11 82 DA 9C 0F 59 EE B8 B9 27 FB D8 F8 21 AA 58 37 8F CE 47 D9 53 A2 A9 FE B5 01 03 29 A5 45 15 47 C5 FA A2 CA 48 69 99 48 FB C5 CC 29 FE 3A 81 0F 7A EC 3C EB 66 7B EE FA 26 95 05 F9 F0 1B 9B E9 8A 1D DC 83 88 2D 87 78 C5 DC 62 30 1B 63 04 43 78 A5 29 85 3E 18 5B 21 12 8B 74 83 60 4D 26 38 5C 16 80 05 04 E3 D4 AA 22 86 3F 91 A0 80 DB 33 CE E6 CC CE 54 6D 3C 49 04 43 AC A6 7B 28 38 F5 A4 65 01 78 C2 9D BE 85 10 2C 3E 52 18 29 0B 0B 71 FE C5 85 FF D1 2D ED D1 35 4E 1C BE 07 37 83 FD D4 D4 F3 66 9E D3 56 41 89 E1 64 92 8E CC F8 9C DB 5E 4E E5 8E 7C 8A B8 90 38 A5 6D A9 43 1E 3B F5 9E D5 44 3D 22 56 36 25 F4 FE D0 54 24 9D 30 E7 46 BB 56 A8 5C B7 FB DA 2B 03 3A 7F 64 90 7D EC 76 F4 4D D3 9E DC 10 2B 22 CD 17 C2 1C 37 37 C3 6D BC 70 97 EB 72 29 3B 14 1B 0D 13 06 2A 98 7C B6 00 60 A9 56
]]
return function(node)
  local X, x = curve.gen_key()
  local B = assert(node.router.ntor_onion_key)
  local ID = assert(node.router.fingerprint)
X=require"blue.hex".decode("31 D5 A8 DF B5 B4 95 1C 72 CD F7 84 72 81 09 75 85 83 F2 84 97 E5 68 E2 52 CA 10 C5 8C 8C 2A 6A")
x=require"blue.hex".decode("A8 C0 E1 C5 B2 5F 94 4C AF 96 F2 30 7E 64 50 36 77 62 CB 1F 6C C1 B4 45 C6 0E A7 E8 21 3A 3B 7B")
B=require"blue.hex".decode("74 1C B6 63 E6 C3 9B 0C 68 42 83 3F C6 44 53 04 0A 47 D4 FB C9 54 7F 8B CF E6 DC 79 F9 EB CB 02")
ID=require"blue.hex".decode("E9 59 55 CD 7A B0 12 DE 77 07 11 87 8F 14 7C 78 4F C1 3D 37")
  local ret = struct.pack(">HHc20c32c32", HANDSHAKE_TYPE_NTOR, ID:len() + B:len() + X:len(), ID, B, X)
  return ret, function(hdata)
    hdata = hdata:sub(3) -- Remove HDATA Len
hdata=require"blue.hex".decode("64 58 15 9C EA 82 4E 4D 5D 5C C0 3E 10 E5 2D F7 78 CD 69 93 F7 8B E9 68 4F 88 C6 F6 62 74 65 5F EA 42 B3 AD B0 E1 F9 43 90 74 A8 93 70 C7 FC E3 2A 0A B7 A1 7B E0 88 66 C2 3F F2 B5 CA 18 BF 97")
    local Y = hdata:sub(1, 32)
    local auth = hdata:sub(33):sub(1, 32)
    local PROTOID = "ntor-curve25519-sha256-1"
    local secret_input = curve.handshake(x, Y) .. curve.handshake(x, B) .. ID .. B .. X .. Y .. PROTOID
--[[print(require"blue.hex".encode(rfc5869(

require"blue.hex".decode("2C 57 3B E3 D7 FF 67 1C 43 E5 EB E1 E2 88 E3 11 52 70 35 08 BF A1 E9 49 F0 41 86 5B BF 52 DC 04 6D 7F F4 1A C3 A5 20 16 67 CF 1D 2D F9 8A 76 B7 4C 43 B8 0C 1C 34 CB B0 3C 75 A3 0A F2 EE 94 20 A9 F5 13 5A E1 8C 7E 25 C7 C7 91 17 CD 8C 76 19 BF EB 85 ED 4D 59 9F B1 A3 FC 4F 19 6D 67 9D 07 F5 82 9A 48 7E F7 A0 BF D3 88 B5 DA 86 A1 CE 6E 3F 90 66 7D 86 C6 56 86 7B 54 9C 79 4D 26 E4 AE 27 66 C6 5E D5 2E D5 2F 81 1E BD 6A 65 07 0C F6 E3 E1 28 53 BB 08 8F 7F 98 3A 51 AF 08 26 2F F8 69 12 39 B3 A8 DD E8 56 16 AF 55 C4 89 8F 82 A9 59 04 90 4C 6E 74 6F 72 2D 63 75 72 76 65 32 35 35 31 39 2D 73 68 61 32 35 36 2D 31")

, PROTOID .. ":key_extract", PROTOID .. ":key_expand")))
--99 66 01 70 E7 DA C1 95 08 0F 24 83 D1 60 10 23 23 28 7A 9C 1A 5F F5 C8 74 54 51 9D AB 83 15 DC 2C 33 B4 B5 A5 F4 27 A6 69 D2 38 18 A9 3D BB 10 60 D7 CE A9 28 10 C5 4B 17 DB 8D 69 28 0C BD FA 46 00 CF BD 94 0A E4 C4 29 C8 0B 57 0B 90 52 16 94 20 18 5C DE B6 4F DC 55 E5 C3 3A
]]
    local seed = hmac(secret_input, PROTOID .. ":key_extract")
    local verify = hmac(secret_input, PROTOID .. ":verify")
    local auth_input = verify .. ID .. B .. Y .. X .. PROTOID .. "Server"
    local auth_v = hmac(auth_input, PROTOID .. ":mac")
    assert(auth_v == auth, "Invalid hash")
    local long_key = rfc5869(secret_input, PROTOID .. ":key_extract", PROTOID .. ":key_expand")
--print(require"blue.hex".encode(long_key))
--99 66 01 70 E7 DA C1 95 08 0F 24 83 D1 60 10 23 23 28 7A 9C 1A 5F F5 C8 74 54 51 9D AB 83 15 DC 2C 33 B4 B5 A5 F4 27 A6 69 D2 38 18 A9 3D BB 10 60 D7 CE A9 28 10 C5 4B 17 DB 8D 69 28 0C BD FA 46 00 CF BD 94 0A E4 C4 29 C8 0B 57 0B 90 52 16 94 20 18 5C DE B6 4F DC 55 E5 C3 3A
    node.digest_forward = long_key:sub(1, 20)
    node.digest_backward = long_key:sub(21, 40)
    node.key_forward = long_key:sub(41, 56)
    node.key_backward = long_key:sub(57, 72)
    KH = long_key:sub(73, 72 + 32)
  end
end

