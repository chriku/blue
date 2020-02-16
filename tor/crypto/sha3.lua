local sha3_stream = require "blue.tor.crypto.sha3_stream"
return function(data)
  return sha3_stream()(data)
end
