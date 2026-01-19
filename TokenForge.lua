--[[
  TokenForge.lua
  � 2025 Kinzin. All rights reserved. [MIT License]
  
  TokenForge � deterministic HMAC-based obfuscator (pure-Lua)
  
  DESCRIPTION
    This ModuleScript provides a deterministic HMAC-SHA256-based obfuscator that
    turns a string (message) into a compact, URL-safe base64 string. The module
    includes a pure-Lua SHA-256 and HMAC-SHA256 implementation and emits a
    base64url-style output which may be truncated or padded to a fixed size.
    
    IMPORTANT SECURITY NOTES
      - Keep your secret key server-side only. NEVER embed the secret in client
        code or in code that can be distributed to end users.
      - This module produces an HMAC-based obfuscation (authenticator), not
        encryption. It proves authenticity of the message given the secret �
        do not treat the result as a confidential ciphertext.
      - Although this implementation uses standard primitives (SHA-256, HMAC),
        prefer audited crypto libraries / server-side crypto APIs for production
        when available.
      - Do not print or log secrets or sensitive tokens in production logs.
      - Because the output is deterministic (same key + same message ? same token),
        include timestamps or nonces in the message if you want expiry or single-use tokens.
      - Verification should be done using constant-time comparison (this module's
        design expects you to compare outputs safely).
    
  API (how to use)
    local mod = require(path.to.TokenForge)
    
    -- 1) Create an obfuscator factory:
    --    obfFactory = mod(keyArg, sizeArg)
    --      - keyArg   : secret key string (server-only)
    --      - sizeArg  : optional output length (number). If given, output will be
    --                   truncated or right-padded with 'A' to this length.
    --    Example:
    --      local obfFactory = mod("my_server_secret", 32)
    --      local token = obfFactory("user:12345")
    --
    -- 2) One-shot call:
    --    You can call the module directly to obtain an obfuscated token immediately:
    --      local token = mod(keyArg, sizeArg, value)
    --    Example:
    --      local token = mod("my_server_secret", 32, "user:12345")
    --
    -- 3) Default behavior:
    --    If you omit sizeArg the module uses a default size of 32 characters.
    --    If you call the module with no keyArg it returns a factory using an
    --    empty key (not secure). Always provide a proper secret in production.
    
  BEHAVIOR DETAILS
    - HMAC: HMAC-SHA256 over the message, returning hex; converted to raw bytes,
      then to a URL-safe base64-like alphabet (A-Z a-z 0-9 - _).
    - Deterministic: identical inputs produce identical outputs.
    - Output sizing: output is truncated to `size` or right-padded with 'A'
      if the encoded output is shorter than requested.
    - Encoding: uses URL-safe alphabet (no padding '=') and omission of trailing
      chars to match requested size.
    
  EXAMPLES
    -- require the module (server-side)
    local TokenForge = require(script.Parent.TokenForge)
    
    -- Factory usage (recommended)
    local secret = "KEEP_THIS_SECRET_ON_SERVER"
    local obfFactory = TokenForge(secret, 32)            -- returns function(value) -> token
    local token = obfFactory("user:12345:asset_xyz")
    -- token is a 32-character string (truncated/padded)
    
    -- One-shot usage
    local oneShot = TokenForge(secret, 32, "user:12345:asset_xyz")
    -- oneShot equals token from obfFactory("user:12345:asset_xyz")
    
    -- Verification (server-side)
    -- Compare obfFactory(message) with stored token using a constant-time compare.
    
  RECOMMENDATIONS
    - Store `secret` in a secure server location (vault, environment, or private ModuleScript
      located under ServerScriptService). Do not commit secrets to source control.
    - For tokens that must expire, include a timestamp inside the message:
        local msg = message .. "|" .. tostring(os.time())
      and validate the timestamp window on verification.
    - For single-use tokens, include a randomly generated nonce and record its use server-side.
    - Prefer using audited crypto libraries or a backend service for high-security needs.
    
  DISCLAIMER
    While this code implements standard SHA-256 and HMAC primitives in Lua, cryptography
    is subtle � review and prefer audited libraries for production-critical systems.
    
  License: MIT
]]--

return function(keyArg, sizeArg, maybeValue)
	local key = keyArg
	local defaultSize = 32
	local bit = bit32
	local bxor = bit.bxor
	local band = bit.band
	local bor = bit.bor
	local bnot = bit.bnot
	local rshift = bit.rshift
	local lshift = bit.lshift

	local function toHex(n) return string.format("%08x", n) end

	local function sha256(msg)
		local K = {
			0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
			0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
			0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
			0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
			0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
			0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
			0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
			0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
		}
		local function ROTR(x,n) return bor(rshift(x,n), lshift(x, 32-n)) end
		local function SHR(x,n) return rshift(x,n) end
		local function Ch(x,y,z) return bxor(band(x,y), band(bnot(x), z)) end
		local function Maj(x,y,z) return bor(bor(band(x,y), band(x,z)), band(y,z)) end
		local function Sigma0(x) return bxor(bxor(ROTR(x,2), ROTR(x,13)), ROTR(x,22)) end
		local function Sigma1(x) return bxor(bxor(ROTR(x,6), ROTR(x,11)), ROTR(x,25)) end
		local function sigma0(x) return bxor(bxor(ROTR(x,7), ROTR(x,18)), SHR(x,3)) end
		local function sigma1(x) return bxor(bxor(ROTR(x,17), ROTR(x,19)), SHR(x,10)) end

		local ml = #msg * 8
		msg = msg .. string.char(0x80)
		while (#msg + 8) % 64 ~= 0 do msg = msg .. string.char(0) end
		for i = 7, 0, -1 do msg = msg .. string.char(band(rshift(ml, i*8), 0xFF)) end

		local H = {
			0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
			0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
		}

		for i = 1, #msg, 64 do
			local w = {}
			for t = 0, 15 do
				local idx = i + t*4
				local b1 = msg:byte(idx) or 0
				local b2 = msg:byte(idx+1) or 0
				local b3 = msg:byte(idx+2) or 0
				local b4 = msg:byte(idx+3) or 0
				w[t] = ((b1 * 256 + b2) * 256 + b3) * 256 + b4
				w[t] = w[t] % 4294967296
			end
			for t = 16, 63 do
				w[t] = (sigma1(w[t-2]) + w[t-7] + sigma0(w[t-15]) + w[t-16]) % 4294967296
			end

			local a,b,c,d,e,f,g,h = H[1],H[2],H[3],H[4],H[5],H[6],H[7],H[8]
			for t = 0, 63 do
				local T1 = (h + Sigma1(e) + Ch(e,f,g) + K[t+1] + w[t]) % 4294967296
				local T2 = (Sigma0(a) + Maj(a,b,c)) % 4294967296
				h = g
				g = f
				f = e
				e = (d + T1) % 4294967296
				d = c
				c = b
				b = a
				a = (T1 + T2) % 4294967296
			end

			H[1] = (H[1] + a) % 4294967296
			H[2] = (H[2] + b) % 4294967296
			H[3] = (H[3] + c) % 4294967296
			H[4] = (H[4] + d) % 4294967296
			H[5] = (H[5] + e) % 4294967296
			H[6] = (H[6] + f) % 4294967296
			H[7] = (H[7] + g) % 4294967296
			H[8] = (H[8] + h) % 4294967296
		end

		local out = ""
		for i = 1, 8 do out = out .. toHex(H[i]) end
		return out
	end

	local function hex_to_raw(hex)
		local t = {}
		for i = 1, #hex - 1, 2 do
			t[#t+1] = string.char(tonumber(hex:sub(i, i+1), 16))
		end
		return table.concat(t)
	end

	local function hmac_sha256(keystr, msg)
		local block = 64
		if #keystr > block then keystr = hex_to_raw(sha256(keystr)) end
		if #keystr < block then keystr = keystr .. string.rep(string.char(0), block - #keystr) end
		local o_key = {}
		local i_key = {}
		for i = 1, #keystr do
			local b = keystr:byte(i)
			o_key[i] = string.char(bxor(b, 0x5c))
			i_key[i] = string.char(bxor(b, 0x36))
		end
		o_key = table.concat(o_key)
		i_key = table.concat(i_key)
		local inner = sha256(i_key .. msg)
		local inner_raw = hex_to_raw(inner)
		local outer = sha256(o_key .. inner_raw)
		return outer
	end

	local b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	local function base64url_from_raw(raw)
		local out = {}
		local i = 1
		while i <= #raw do
			local b1 = raw:byte(i) or 0
			local b2 = raw:byte(i+1) or 0
			local b3 = raw:byte(i+2) or 0
			local n = b1 * 65536 + b2 * 256 + b3
			local c1 = band(rshift(n, 18), 0x3F) + 1
			local c2 = band(rshift(n, 12), 0x3F) + 1
			local c3 = band(rshift(n, 6), 0x3F) + 1
			local c4 = band(n, 0x3F) + 1
			out[#out+1] = b64:sub(c1,c1)
			out[#out+1] = b64:sub(c2,c2)
			out[#out+1] = b64:sub(c3,c3)
			out[#out+1] = b64:sub(c4,c4)
			i = i + 3
		end
		local rem = #raw % 3
		if rem == 1 then
			out[#out] = nil
			out[#out] = nil
		elseif rem == 2 then
			out[#out] = nil
		end
		return table.concat(out)
	end

	local function make_obfuscator(keyParam, sizeParam)
		local s = tonumber(sizeParam) or defaultSize
		return function(value)
			local msg = tostring(value or "")
			local mac = hmac_sha256(tostring(keyParam or ""), msg)
			local raw = hex_to_raw(mac)
			local enc = base64url_from_raw(raw)
			if s and s > 0 then
				if #enc >= s then
					return enc:sub(1, s)
				else
					return enc .. string.rep("A", s - #enc)
				end
			else
				return enc
			end
		end
	end

	if keyArg == nil then
		return make_obfuscator("", defaultSize)
	end

	if maybeValue ~= nil then
		local size = tonumber(sizeArg) or defaultSize
		local obf = make_obfuscator(keyArg, size)
		return obf(maybeValue)
	end

	if type(sizeArg) == "number" or tonumber(sizeArg) then
		return make_obfuscator(keyArg, sizeArg)
	end

	local valueIfSecondIsNotNumber = sizeArg
	if valueIfSecondIsNotNumber ~= nil then
		local obf = make_obfuscator(keyArg, defaultSize)
		return obf(valueIfSecondIsNotNumber)
	end

	return make_obfuscator(keyArg, defaultSize)
end
