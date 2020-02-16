local sha3_stream = require "blue.tor.sha3_stream"
return function(data)
  return sha3_stream()(data)
end
