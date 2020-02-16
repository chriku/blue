local hex = {}
function hex.encode(a)
  if not a then
    error("Invalid tohex string", 2)
  end
  return (a:gsub(".", function(a)
    return string.format("%02X ", string.byte(a))
  end):sub(1, -2))
end
function hex.decode(a)
  local ret = ""
  for b in a:gmatch("[0-9A-F][0-9A-F]") do
    ret = ret .. string.char(tonumber(b, 16))
  end
  return ret
end
return hex
