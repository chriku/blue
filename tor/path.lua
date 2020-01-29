local dir = require "blue.tor.dir"
local ntor = require "blue.tor.ntor"
local struct = require "blue.struct"
local aes=require"blue.tor.aes"
local sha1=require"blue.sha1"
return function(circuit, first_node_info)
  local first_node = {router = dir.parse_to_router(first_node_info)}
  local path = {}
  local handshake_data, handshake_cb = ntor(first_node)
handshake_cb("")
  circuit:send_cell("create2", handshake_data)
  do
    --local cmd, data = circuit:read_cell()
    --assert(cmd == "created2")
    --handshake_cb(data)
  end
  function path:extend(node_info)
    local new_node = {router = dir.parse_to_router(node_info)}
    local ip1, ip2, ip3, ip4 = assert(new_node.router.address):match("^([0-9]+)%.([0-9]+)%.([0-9]+)%.([0-9]+)$")
    ip1 = assert(tonumber(ip1))
    ip2 = assert(tonumber(ip2))
    ip3 = assert(tonumber(ip3))
    ip4 = assert(tonumber(ip4))
    local handshake_data, handshake_cb = ntor(new_node)
    local extend_content = struct.pack(">B BB BBBB H", 1, 0, 6, ip1, ip2, ip3, ip4, assert(new_node.router.orport))..handshake_data
    local relay_content_hash=struct.pack(">BHHIH",14,0,0,0,extend_content:len())..extend_content
    relay_content_hash=relay_content_hash..string.rep(string.char(0),509-relay_content_hash:len())
relay_content_hash=require"blue.hex".decode("0E 00 00 00 00 00 00 00 00 00 77 02 00 06 05 87 A2 31 23 29 02 14 49 5B 49 68 67 C8 4B BC 92 33 83 01 D9 24 85 0F 22 6E 75 DA 00 02 00 54 49 5B 49 68 67 C8 4B BC 92 33 83 01 D9 24 85 0F 22 6E 75 DA 1B 23 AA 40 64 48 3F FA 15 DC E0 8C C2 AB 0F 08 36 72 6F 5E F8 CD 86 7B 88 B5 E6 87 D9 1C 8D 0A 9D 67 73 50 43 CD C6 6F 74 21 4A 13 08 79 30 89 73 CF 5F 78 DC 36 06 28 F1 15 E2 F5 C8 7C 09 22 00 00 00 00 6A 5F 58 4C 76 9C C2 2D F8 45 6F 2C AC FE 3A D5 77 D8 10 93 BA E4 F0 E7 FF A7 CB 5E CD 8C 37 AF 10 55 5B 19 98 90 4D C8 E4 64 4A 6F 4E E8 6B E3 4F 08 4C DC 86 4C 96 50 64 20 B0 2F 30 DA C7 97 28 DA 9E EC 44 E1 88 8F B2 BF 24 3D 4F 9F 9F 4B A3 88 D4 5A 03 E5 9A 94 35 B3 3A DD 40 ED 02 FF 2D 2F 1F 06 42 F5 86 F4 9B 62 9D BD 2B E4 E5 11 DC AE F9 5D 0B 73 D8 D2 8A 7E F5 A1 E3 D7 2A 49 9F 01 0A F7 9C 79 56 77 83 73 E9 6B 2B A7 A3 6E 16 25 62 42 41 AA DE F9 C3 4C FE 5C 3D 2C 41 62 53 AD B4 11 96 81 CA CE 66 43 52 D4 2C 2E 0B 54 A1 2D 6A 55 2C E6 D8 6F 58 20 7D 1A 2F 69 78 C9 45 07 75 5C B5 AE E5 0C C6 3D A7 9E FE BD 9F D9 65 D8 19 5A 26 01 1C 77 D7 4A E8 28 9E 9D BE FA 66 31 3C 22 36 93 62 AA 42 CD 79 63 82 6A 44 84 C0 34 87 8D 9F AD C1 F5 40 4B 45 27 3B 5C D2 31 2F A9 45 8C 68 77 51 8A 90 CD B6 D2 C2 FE 18 B8 72 D7 D3 D7 65 AA F9 3D 9A DF CA AF DE 89 D7 1A A0 C9 FF E0 60 62 BB 52 37 53 2C B5 E8 06 B1 CE 2D 54 5C 11 AD EB C0 2B B7 07 36 10 69 BB 6D 96 8D 91 C5 00 6B 8F EB 89 85 72 88 8D 74 3B F0 41 EF E5 79 B0 69 DD 02 19 B6 D7 79 D2 0B 05 DB A4 B0 AF F6 28 0F AD 29 C2 BB D4 10 4F C0 EB 6D 98 5B DC 64 3F 68 8F D1")
    local digest=sha1.binary(first_node.digest_forward..relay_content_hash):sub(1,4)
    local relay_content=struct.pack(">BHHc4H",14,0,0,digest,extend_content:len())..extend_content
    relay_content=relay_content..string.rep(string.char(0),509-relay_content:len())
relay_content=relay_content_hash:sub(1,5)..digest..relay_content_hash:sub(10)
print(require"blue.hex".encode(relay_content))
    --circuit:send_cell("relay_early",
--print(require"blue.hex".encode(
assert(aes.encrypt(first_node.key_forward,relay_content)==require"blue.hex".decode("5C 6E E5 EE BB 47 62 7D 5A 68 80 D8 31 EA D0 3A 6E 5B 83 BB E8 9D FB 77 A2 35 82 09 C2 7C CA FC D7 59 0D AB 34 68 8F 7B BB 95 07 CA E3 B0 0D C0 83 11 A1 DD 01 9F 3D 50 C0 AE 48 99 45 16 65 11 FD BC 8A 53 86 29 11 1C 71 42 B1 34 DC BD D0 66 6C A6 45 BD 7E D9 8B 38 14 B7 BD 2D 86 49 03 8C 1B 79 D9 BE FB 60 A0 EE B6 D8 85 C1 1A 19 1A 15 04 18 8B 99 52 98 5F 3B 9C 1C 3F 68 D6 28 34 44 FC 6D 85 B0 B8 63 77 54 74 01 6A 8D 20 15 CD B3 F5 E4 00 0B D7 74 40 39 6A 69 BA 24 5E 8D 60 CF EC 10 B9 B4 3B 05 E7 C6 90 31 90 A0 6E 54 AA 33 E5 8F 83 5C F4 1D 4C 77 6D 38 9B A0 B4 11 C1 24 60 6F A4 6E 25 5F 13 F1 8E 87 72 6A D9 00 AB 94 4E EC 38 38 8E 16 CE 3D C8 7B 2A E3 AC F4 FE 2F D4 E5 E4 CC FD 94 C3 39 FE 52 DF C2 21 93 E6 A4 DB 95 B2 82 B7 29 EC BE 49 1E 49 EC 48 F1 2A FF 29 50 B6 9E CB 22 F0 A5 AE 6C A4 1C 20 90 95 A2 DC A5 A5 47 64 02 61 26 F0 FB 09 D5 DF E0 C9 DF 0C 30 DE 1C 69 1C A7 8C B2 68 5F C8 89 D1 DE 0B A1 BE 93 FD 42 32 EC 03 0E CC 1E F1 00 33 3F F6 8A 8B 78 06 B4 9F 50 2B 2E 46 85 9C A2 35 36 76 EF 2F C4 6A 29 54 4E 71 5F FC E6 FC EE 6C 26 8D A8 4F FC 24 81 50 5C 85 97 73 3D B9 7C BB D6 8E 6B E4 57 4A 4E 62 FF E4 7F F9 3B 35 31 38 9D 4A 2E 7D 3E 38 75 AC DF A5 56 07 78 08 91 8F 3A C7 C8 3B C8 FB 30 16 41 F3 6A F0 39 3C 5D A0 E3 F8 88 50 1C 33 E2 3E 15 3F B1 CA 37 4D 70 B1 85 59 15 88 D5 FE 1E B9 4C 13 92 1D F0 F8 09 05 BC 73 B3 98 68 8C 99 D0 29 3A EE D3 8D 53 58 D5 58 07 29 6F F8 6D 20 8E E7 84 37 D2 32 B1 C4 83 68 58 70 9E E8 2B 84 A0 36 9C DB 9C 8F 37 F8 AA 33 06 F0 CE 67 75 4A FB A0 81 34 BD E5 14 11"),"Invalid Send")
    --circuit:send_cell("relay",relay_content)
    local cmd,data=circuit:read_cell()
    print("EXTEND RESPONSE",cmd,({[0] = "NONE", "PROTOCOL", "INTERNAL", "REQUESTED", "HIBERNATING", "RESOURCELIMIT", "CONNECTFAILED", "OR_IDENTITY", "OR_CONN_CLOSED", "FINISHED", "TIMEOUT", "DESTROYED", "NOSUCHSERVICE"})[string.byte(data)])
  end
  return path
end
