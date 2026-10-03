-- examples/hello_obfuscated.lua
--
-- Hand-written "obfuscation": pointless indirection around constants, so the
-- variable names tell you nothing about the values. This is the same shape as
-- what real obfuscators emit, just tiny enough to read by eye.
--
-- Run it:
--   python env_logger.py examples/hello_obfuscated.lua -o logged.lua
--
-- logged.lua should contain the reconstructed calls, not the variable names:
--   print("Hello, world!")
--   print(246)

local function id(x) return x end

local greeting = id(id(id("Hello, world!")))
local answer = id(id(id(246)))

print(greeting)
print(answer)