PREFETCHED_DNS = {
	["twitter.com"] = "199.59.150.7";
	["pbs.twimg.com"] = "199.96.57.7";
	["abs.twimg.com"] = "199.96.57.7";
	["www.google.com"] = "173.194.72.105";
	["www.google.com.hk"] = "173.194.72.94";
	["www.google.co.jp"] = "173.194.72.94";
}

--
-- Shadowsocks Implement in Lua
-- This program can help you cross your company's firewall.
-- by zyxwvu <imzyxwvu@icloud.com>
--

uv = require "xuv"
local bxor, band, schar = (bit or bit32).bxor, (bit or bit32).band, string.char

if jit and jit.os == "Linux" then
	ffi = require "ffi"
	ffi.cdef[[void (*signal(int signum,void(* handler)(int)))(int);]]
	ffi.C.signal(13, function() end) -- Ignore SIGPIPE
end

HTTP = require "HTTP"

--------------------------------------------------------------------------------
------------------------------   Name Resolving   ------------------------------
--------------------------------------------------------------------------------

DNS = {
	A = 0x01, CNAME = 0x05, MX = 0x0F, TXT = 0x10, Cache = PREFETCHED_DNS
}

function DNS.PackHost(host)
	local result = {}
	for p in host:gmatch("([^%.]+)") do
		assert(#p < 128, "part of hostname too long")
		result[#result + 1] = schar(#p) .. p
	end
	result[#result + 1] = "\0"
	return table.concat(result)
end

function DNS.MakeReq(query)
	local header = schar(
		0, query.id or 0, -- Query ID
		query.rc and 1 or 0,  0,  0, 1,  0, 0,  0, 0,  0, 0)
	return header .. DNS.PackHost(query[1]) ..
		schar(0, query.type or 1, 0, 1)
end

function DNS.ParseRes(resp)
	if #resp < 12 then error"header not complete" end
	local result = { }
	local b1, b2, b3, b4 = resp:byte(5, 8)
	local nres, nref, nar = b4, resp:byte(10, 10), resp:byte(12, 12)
	result.id = resp:byte(2, 2)
	result.rcode = band(resp:byte(4, 4), 0xF)
	local ptr = 13
	function extractName()
		local name = {}
		local ptrBackup
		while true do
			local l = resp:byte(ptr, ptr)
			ptr = ptr + 1
			if l == 0xC0 then
				if not ptrBackup then ptrBackup = ptr + 1 end
				ptr = resp:byte(ptr, ptr) + 1
			elseif l == 0 then break
			elseif not l then error"name not complete"
			else
				name[#name + 1] = resp:sub(ptr, ptr + l - 1)
				ptr = ptr + l
			end
		end
		if ptrBackup then ptr = ptrBackup end
		return table.concat(name, ".")
	end
	result.name = extractName()
	ptr = ptr + 1
	result.type = resp:byte(ptr)
	ptr = ptr + 3
	function extractRecord()
		local result = {}
		result.rname = extractName()
		ptr = ptr + 1
		result.rtype = resp:byte(ptr)
		ptr = ptr + 3
		b1, b2, b3, b4 = resp:byte(ptr, ptr + 3)
		result.rttl = b1 * 0x1000000 + b2 * 0x10000 + b3 * 0x100 + b4
		ptr = ptr + 4
		b1, b2 = resp:byte(ptr, ptr + 1)
		local len, ptrBackup = b1 * 0x100 + b2, ptr
		if result.rtype == 1 and len == 4 then
			result.data = ("%d.%d.%d.%d"):format(resp:byte(ptr + 2, ptr + 5))
		elseif result.rtype == 5 or result.rtype == 2 or result.rtype == 6 then
			ptr = ptr + 2; result.data = extractName();
		else
			result.data = resp:sub(ptr + 2, ptr + len + 1)
		end
		ptr = ptrBackup + len + 2
		return result
	end
	if nres > 0 then
		result.records = {}
		for i = 1, nres do result.records[i] = extractRecord() end
	elseif nref > 0 then
		result.aa, result.records = true, {}
		for i = 1, nref do result.records[i] = extractRecord() end
		for i = 1, nar do
			local append = extractRecord()
			for i, v in ipairs(result.records) do
				if append.rtype == 1 and append.rname == v.data then
					v.addr = append.data
				end
			end
		end
	end
	return result
end

function DNS.ToIP(name, callback)
	if DNS.Cache[name] then
		callback(DNS.Cache[name])
	else
		local handle = uv.udp_new()
		local dnsQuery = DNS.MakeReq{name, type = 1, rc = true}
		local s_time = os.clock()
		uv.udp_send(handle, dnsQuery, "8.8.8.8", 53)
		uv.udp_send(handle, dnsQuery, "114.114.114.114", 53)
		local watchdog = uv.timer_new()
		uv.timer_start(watchdog, function()
			uv.close(handle)
			uv.close(watchdog)
			callback(nil, "timeout")
		end, 1500)
		uv.udp_recv_start(handle, function(blk, peer)
			local s, result = pcall(DNS.ParseRes, blk)
			if s then
				uv.close(watchdog)
				uv.close(handle)
				if result.rcode == 3 or not result.records then
					callback(nil, "bad name")
					return
				end
				local cname
				for i, v in ipairs(result.records) do
					if v.rtype == 1 then
						result = v.data
						print((" * state: name %s resolved: %s"):
							format(name, result))
						if cname then
							print(("   ( CNAME = %s ) "):
								format(cname))
						end
						print((" * statistic: by %s in %.1f secs"):
							format(peer, os.clock() - s_time))
						DNS.Cache[name] = result
						callback(result)
						return
					elseif v.rtype == 5 then cname = v.data end
				end
				callback(nil, "no A result")
			else
				print((" * invaild DNS packet by: %s"):format(peer))
			end
		end)
	end
end

--------------------------------------------------------------------------------
------------------------------ Proxy  Controlling ------------------------------
--------------------------------------------------------------------------------

GFWTree, GFWList = {}, {}

function ReadGFWHosts(gfwhosts)
	local fp = io.open(gfwhosts or "gfwhosts.txt", "r")
	if fp then
		GFWTree, GFWList = {}, {}
		for l in fp:lines() do
			if l:sub(1, 1) ~= "#" and l:find("[^%s\t]+") then
				l = l:match("^[%s\t]*([^%s\t]+)[%s\t]*$")
				if l:find("^%d+%.%d+%.%d+%.%d+$") then
					GFWList[l] = true
				else
					local name = {}
					for p in l:gmatch "[^%.]+" do
						name[#name + 1] = p
					end
					local nftree = GFWTree
					for i = #name, 1, -1 do
						if not nftree[name[i]] then
							nftree[name[i]] = {}
						end
						nftree = nftree[name[i]]
					end
					nftree[1], nftree[2] = true, l:sub(1, 1) == "."
				end
			end
		end
		fp:close()
	end
end

function NeedForward(ipaddr, name_str)
	if GFWList[ipaddr] then return true end
	if not name_str then return false end
	local name = {}
	for p in name_str:gmatch "[^%.]+" do
		name[#name + 1] = p
	end
	local nftree = GFWTree
	for i = #name, 1, -1 do
		nftree = nftree[name[i]]
		if not nftree then break end
		if nftree[2] then break end
	end
	if nftree then
		if nftree[1] then
			if ipaddr then GFWList[ipaddr] = name_str end
			return true
		end
	end
	return false
end

ReadGFWHosts()

--------------------------------------------------------------------------------
------------------------------    Web  Service    ------------------------------
--------------------------------------------------------------------------------

function web_service_connect(res, host, port)
	local co = coroutine.running()
	local address
	if host:find("^%d+%.%d+%.%d+%.%d+$") then
		address = host
	else
		if DNS.Cache[host] then -- coroutine issue
			address = DNS.Cache[host]
		else
			DNS.ToIP(host, function(...)
				HTTP.SafeResume(co, ...)
			end)
			local result = coroutine.yield()
			if result then
				address = result
			else
				return res:DisplayError(502, "UNKNOWN DNS NAME")
			end
		end
	end
	if false and NeedForward(address, host) then
		-- Coming later...
	else
		uv.connect(address, port, function(...)
			HTTP.SafeResume(co, ...)
		end)
		local stream, err = coroutine.yield()
		if stream then
			print(" * HTTP: plain connected to: " .. host)
			res:WriteHeader(200, {})
			-- downgrade the stream
			res.disabled = true
			res.reader:Push(nil, "downgraded")
			-- pipe the streams
			function stream.on_close() res.stream:close() end
			function stream.on_data(chunk)
				stream:read_stop()
				res.stream:write(chunk, function(err)
					if not err and stream() then
						stream:read_start()
					end
				end)
			end
			if res.reader.buffer then
				stream:write(res.reader.buffer)
				res.reader.buffer = nil
			end
			function res.stream.on_close(err) stream:close() end
			function res.stream.on_data(chunk)
				res.stream:read_stop()
				stream:write(chunk, function(err)
					if not err and res.stream() then
						res.stream:read_start()
					end
				end)
			end
			stream:read_start()
			if res.reader.paused then res.stream:read_start() end
		else
			return res:DisplayError(502, err or "BAD PROXY")
		end
	end

end

function web_service(req, res)
	print((" * Web Service: %s %s %s"):format(req.peername, req.method, req.resource_orig))
	if req.method == "CONNECT" then
		local host, port = req.resource_orig:match("^([A-Za-z0-9%-%.]+):(%d+)$")
		if host and port then
			res.reader = req.reader
			return web_service_connect(res, host, assert(tonumber(port)))
		else
			res:DisplayError(400, "BAD REQUEST")
		end
	elseif req.method == "BREW" or req.method == "WHEN" then
		res:DisplayError(418, [[<html><body><h1>I'm a teapot</h1></body></html>]])
	elseif req.resource == "/" then
		if req.headers["user-agent"] then
			if req.headers["user-agent"]:find("CFNetwork/", 1, true) then
				print(" * state: PAC file sent to - " .. req.peername)
				local sockname = res.stream:getsockname()
				local PAC = string.format([[
function FindProxyForURL(url, host) {  // for iOS
	if(url.toLowerCase().substr(0, 8) == "https://") return "PROXY %s:2333";
	else return "SOCKS %s:2333"; } ]], sockname, sockname)
				res:WriteHeader(200, {
					["Content-Type"] = "application/x-ns-proxy-autoconfig",
					["Content-Length"] = #PAC })
				res:RawWrite(PAC)
				return
			end
		end
	elseif req.resource == "/pcl-add" and req.peername == "127.0.0.1" then
		if #req.query > 0 and req.headers.referer then
			GFWList[req.query] = req.peername
			res:RedirectTo(req.headers.referer) -- go back!
		else
			res:DisplayError(500, "<html><body><h1>Bad usage</h1></body></html>")
		end
	else res:RedirectTo "/" end
end

GREEN_WEB_TIP = [[<!DOCTYPE html>
<html><head><title>绿色上网告示</title></head><body>
	<style> body { background-color: #DFD; font-family: "幼圆", sans-serif; } h1 { text-align: center; font-family: "华文彩云"; } </style>
	<h1>绿色上网告示</h1>
	<p>什么，你还在访问这家同性交友网站？</p>
	<p>根据工信部和文化部的联合调查报儿童告，该同性交友网站受到一个境外组织控制，站在党和人民的对立面，长期以来向中国的青少年儿童提供色情、血腥动画，蛊惑了我国大量的青少年。据统计，我国每年都有数千万青少年因为这种动画而患上一种叫做中二病的心理疾病。</p>
	<p>如果需要观看动画，我们推荐你点击下面的链接，观看适宜青少年儿童观众的、具有社会主义特色的国产动画。</p>
	<p><a href="http://tv.sohu.com/s2012/hlxd/">点击观看</a></p>
</body></html>]]

function web_service_lvba(req, res)
	if req.resource == "/" then
		res:WriteHeader(200, {
			["Content-Type"] = "text/html; charset=UTF-8",
			["Content-Length"] = #GREEN_WEB_TIP
		})
		res:RawWrite(GREEN_WEB_TIP)
	else res:RedirectTo "/" end
end

--------------------------------------------------------------------------------
------------------------------     Shadowsocks    ------------------------------
--------------------------------------------------------------------------------

crypto = require "crypto"

Shadowsocks = { password = "12345", " * Clowwindy I love you! -- zyxwvu" }

Shadowsocks.forwarder = {
	assert(arg[1], "usage: ShadowSocks.lua server_ip [server_port]"),
	tonumber(arg[2]) or 8388
}

if false then print(Shadowsocks[1]) end

function Shadowsocks.random_string(length)
	local buffer = {}
	for i = 1, length do buffer[i] = math.random(0, 255) end
	return schar(unpack(buffer))
end

function Shadowsocks.evp_bytestokey(password, key_len, iv_len)
	local key = string.format("%s-%d-%d", password, key_len, iv_len)
	local m, i = {}, 0
	while #(table.concat(m)) < key_len + iv_len do
		local data = password
		if i > 0 then data = m[i] .. password end
		m[#m + 1], i = crypto.digest("md5", data, true), i + 1
	end
	local ms = table.concat(m)
	local key = ms:sub(1, key_len)
	local iv = ms:sub(key_len + 1, iv_len)
	return key, iv
end

function Shadowsocks.rc4_md5(wtf, key, iv)
	local md5 = crypto.digest.new "md5"
	md5:update(key)
	md5:update(iv)
	return wtf.new("rc4", md5:final(nil, true), "")
end

function Shadowsocks.connect(ip, port, callback)
	local key_ = Shadowsocks.evp_bytestokey(Shadowsocks.password, 16, 16)
	local cipher_iv = Shadowsocks.random_string(16)
	local cipher, decipher
	cipher = Shadowsocks.rc4_md5(crypto.encrypt, key_, cipher_iv)
	uv.connect(Shadowsocks.forwarder[1], Shadowsocks.forwarder[2], function(self, err)
		if err then return callback(nil, err) end
		local a, b, c, d = ip:match "^(%d+)%.(%d+)%.(%d+)%.(%d+)$"
		a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
		assert(a and b and c and d)
		self:write(cipher_iv .. cipher:update(
			schar(1, a, b, c, d, band(port, 0xFF00) / 0x100, band(port, 0xFF))))
		local agent = {}
		function self.on_data(chunk)
			if decipher then
				chunk = decipher:update(chunk)
				if #chunk > 0 then agent.on_data(chunk) end
			else
				if #chunk >= 16 then
					local key_ = Shadowsocks.evp_bytestokey(Shadowsocks.password, 16, 16)
					decipher = Shadowsocks.rc4_md5(crypto.decrypt,key_, chunk:sub(1, 16))
					if #chunk > 16 then
						chunk = decipher:update(chunk:sub(17, -1))
						if #chunk > 0 then agent.on_data(chunk) end
					end
				end
			end
		end
		function self.on_close(reason)
			if agent.on_close then agent.on_close(reason) end
		end
		function agent.write(_, chunk, callback)
			local cipherdata = cipher:update(chunk)
			if #cipherdata > 0 then
				self:write(cipherdata, callback)
			else
				return callback()
			end
		end
		function agent.close(reason) return self:close(reason) end
		function agent.read_start() return self:read_start() end
		function agent.read_stop() return self:read_stop() end
		function agent.alive() return self() end
		return callback(agent)
	end)
end

--------------------------------------------------------------------------------
------------------------------   Proxy  Service   ------------------------------
--------------------------------------------------------------------------------

function shadow_service(stream, request, socks_rest)
	Shadowsocks.connect(request.address, request.r_port, function(remote, err)
		if err then
			print(" * error: failed to connect to " .. request.address)
			return request.fail()
		end
		print(" * shadowsocks: connected to " .. (request.host or request.address))
		if socks_rest then
			stream:write(schar(0, 0, 1, 0, 0, 0, 0, 0x10, 0x10))
			if #socks_rest > 0 then remote:write(socks_rest) end
		end
		function remote.on_close() stream:close() end
		function stream.on_close() remote:close() end
		function remote.on_data(chunk)
			remote:read_stop()
			clean_stream = false
			if stream() then stream:write(chunk, function()
				if remote:alive() then remote:read_start() end
			end) end
		end
		function stream.on_data(chunk)
			stream:read_stop()
			if remote:alive() then remote:write(chunk, function()
				if stream() then stream:read_start() end
			end) end
		end
		remote:read_start()
		stream:read_start()
	end)
end

function plain_service(stream, request, socks_rest)
	uv.connect(request.address, request.r_port, function(remote, err)
		if err then
			print(" * error: failed to connect to " .. request.address)
			return request.fail()
		end
		print(" * state: connected to " .. (request.host or request.address))
		local clean_stream = request.r_port == 80 and socks_rest
		if not stream() then return end
		function stream.on_close() remote:close() end
		function remote.on_close(reason)
			if reason == "ECONNRESET" and clean_stream then
				local response = {
					"HTTP/1.1 502 GFWed",
					"Content-Type: text/html",
					"Connection: close",
					"",
					string.format([[<html><head><title>Shadowsocks Lua</title></head>
<body style="font-family: arial;"><h1>Shadowsocks Lua has Detected a GFW Behavior</h1>
<p>The site <b>%s</b> seems to be GFWed. If you want to visit this page, click the following link:</p>
<a href="http://proxycontrol.arpa/pcl-add?%s">Add to Proxy Controlling List</a></body></html>]],
						request.host or request.address, request.address)
				}
				stream:write(table.concat(response, "\r\n"), function()
					stream:close() -- Defered closing
				end)
			else
				stream:close()
			end
		end
		remote:nodelay(true)
		if socks_rest then
			local peername, peerport = remote:getpeername()
			local a, b, c, d = peername:match "^(%d+)%.(%d+)%.(%d+)%.(%d+)$"
			a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
			assert(a and b and c and d)
			stream:write(schar(0, 0, 1, a, b, c, d,
				band(peerport, 0xFF00) / 0x100, band(peerport, 0xFF)))
			if #socks_rest > 0 then remote:write(socks_rest) end
		end
		function remote.on_data(chunk)
			remote:read_stop()
			clean_stream = false
			if stream() then stream:write(chunk, function()
				if remote() then remote:read_start() end
			end) end
		end
		function stream.on_data(chunk)
			stream:read_stop()
			if remote() then remote:write(chunk, function()
				if stream() then stream:read_start() end
			end) end
		end
		remote:read_start()
		stream:read_start()
	end)
end

function service(stream, request, rest)
	if not request.address and request.host and rest then
		if request.host == "proxycontrol.arpa" then
			stream:write(schar(0, 0, 1, 127, 0, 0, 1, 0, 80))
			return HTTP.HandleStream(stream, rest, web_service)
		end
		if request.host:find "%.bilibili%.com%.?$" and request.r_port == 80 then
			print " * GreenDad: crabbed connection to an R-18 website"
			stream:write(schar(0, 0, 1, 127, 0, 0, 1, 0, 80))
			return HTTP.HandleStream(stream, rest, web_service_lvba)
		end
		DNS.ToIP(request.host, function(address)
			if address then
				request.address = address
				service(stream, request, rest)
			else
				return request.fail()
			end
		end)
		return
	end
	if NeedForward(request.address, request.host) then
		return shadow_service(stream, request, rest)
	else
		return plain_service(stream, request, rest)
	end
end

math.randomseed(os.time()) -- seed Lua's RNG
uv.set_process_title("Shadowsocks Lua")

if jit.os == "Linux" then
	-- Transparent Proxy for Linux
	uv.listen("127.0.0.1", 2336, 32, function(self)
		self:nodelay(true)
		local request = {}
		request.address, request.r_port = self:originaldst()
		if not request.address or request.address == "127.0.0.1" then
			self:close()
			return
		end
		function request.fail() self:close() end
		if NeedForward(request.address, request.host) then
			return shadow_service(self, request, rest)
		else
			return plain_service(self, request, rest)
		end
	end)
end

uv.listen("0.0.0.0", 2333, 32, function(self)
	self:nodelay(true)
	local buffer, nstage, state = "", 1, { stream = self }
	local function handshake()
		if nstage == 1 then
			if #buffer >= 2 then
				local a, b = buffer:byte(1, 2)
				if a == 5 and b > 0 then
					state.nmethods = b
					nstage = 2
				elseif a == 4 and b == 1 then
					return self:close()
				else
					self:read_stop()
					HTTP.HandleStream(self, buffer, web_service)
					buffer = nil
					return
				end
				buffer = buffer:sub(3, -1)
			end
		elseif nstage == 2 then
			if #buffer >= state.nmethods then
				buffer = buffer:sub(state.nmethods + 1, -1)
				self:write "\x05\x00"
				nstage = 3
			end
		elseif nstage == 3 then
			if #buffer >= 4 then
				local v, c, r, a = buffer:byte(1, 4)
				if v == 5 and c == 1 and (a == 1 or a == 3) then
					state.atype = a
					nstage, buffer = 4, buffer:sub(5, -1)
					return true
				else
					self:write(
						"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00",
						function() self:close() end)
				end
			end
		elseif nstage == 4 then
				if state.atype == 3 then
					if #buffer >= 1 then
						state.namelen = buffer:byte(1, 1)
						nstage, buffer = "name", buffer:sub(2, -1)
					end
				elseif state.atype == 1 then
					if #buffer >= 4 then
						local a, b, c, d = buffer:byte(1, 4)
						state.address = ("%d.%d.%d.%d"):format(a, b, c, d)
						nstage, buffer = 5, buffer:sub(5, -1)
					end
				end
		elseif nstage == "name" then
			if #buffer >= state.namelen then
				state.host = buffer:sub(1, state.namelen)
				nstage, buffer = 5, buffer:sub(state.namelen + 1, -1)
				if state.host:find("^%d+%.%d+%.%d+%.%d+$") then
					state.address = state.host
				end
			end
		elseif nstage == 5 then
			if #buffer >= 2 and self() then
				local a, b = buffer:byte(1, 2)
				state.r_port = a * 0x100 + b
				nstage, buffer = 8, buffer:sub(3, -1)
				self:write "\x05"
				self:read_stop()
				self.on_data = nil
				local s, err = pcall(service, self, state, buffer)
				if not s and err then
					print(" * Lua error: " .. err)
				end
				buffer = nil
			end
		else
			error("never reaches here: " .. tostring(nstage))
		end
	end
	function state.fail()
		if self() then
			if not self:write("\x01\x00\x01\x00\x00\x00\x00\x00\x00", function()
				self:close()
			end) then self:close() end
		end
	end
	function self.on_data(chunk)
		buffer = buffer .. chunk
		local reference_buffer
		repeat
			reference_buffer = buffer
			handshake()
			if not buffer then return end
		until reference_buffer == buffer
	end
	self:read_start()
end)

uv.run()