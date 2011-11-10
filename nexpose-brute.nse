description=[[
Performs brute force password auditing against a Nexpose vulnerability scanner using the API 1.1.
]]

---
-- @output
-- PORT     STATE SERVICE     REASON  VERSION
-- 3780/tcp open  ssl/nexpose syn-ack NeXpose NSC 0.6.4
-- | nexpose-brute: 
-- |   Accounts
-- |     nxadmin:nxadmin - Valid credentials
-- |   Statistics
-- |_    Performed 5 guesses in 1 seconds, average tps: 5

author = "Vlatko Kosturjak"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"intrusive", "brute"}

require "shortport"
require "brute"
require "comm"
require "stdnse"

portrule = shortport.port_or_service(3780, "nexpose", "tcp")

local DEFAULT_THREAD_NUM = 2

Driver = 
{
	new = function (self, host, port)
		local o = { host = host, port = port }
		setmetatable (o,self)
		self.__index = self
		return o
	end,

	connect = function ( self )
		self.socket = nmap.new_socket() 
		if ( not(self.socket:connect(self.host, self.port, "ssl")) ) then
			return false
		end
		return true	
	end,

	login = function( self, username, password )
		local status, err
		local res = ""
		local header = { ["Content-Type"] ="text/xml" } 
		local options = { header = header }

		local postdata='<?xml version="1.0" encoding="UTF-8"?><LoginRequest sync-id="1" user-id="'..username..'" password="'..password..'"></LoginRequest>'
		stdnse.print_debug(4, "nexpose-brute: Using: %s", postdata)

		local req = http.post( self.host, self.port, '/api/1.1/xml', options, nil, postdata )

		if (not(req["status"])) then
			return false, "nexpose-brute: Couldn't send/receive HTTPS request" 
		end

		body = req["body"]

		if (not body == nil) then
			stdnse.print_debug(2, "nexpose-brute: Bad login: %s", body)
			return false, brute.Error:new( "Bad login" )
		end

		if (body == nil or string.match(body,'<LoginResponse.*success="0"')) then
			stdnse.print_debug(2, "nexpose-brute: Bad login: %s/%s", username, password)
			return false, brute.Error:new( "Bad login" )
		elseif (string.match(body,'<LoginResponse.*success="1"')) then
			stdnse.print_debug(1, "nexpose-brute: Good login: %s/%s", username, password)
			return true, brute.Account:new(username, password, creds.State.VALID)
		end
		stdnse.print_debug(1, "nexpose-brute: WARNING: Unhandled response: %s", body)
		return false, brute.Error:new( "incorrect response from server" )
	end,

	disconnect = function( self )
		self.socket:close()
	end,
}

action = function(host, port)
	local thread_num = stdnse.get_script_args("nexpose-brute.threads") or DEFAULT_THREAD_NUM
	if not pcall(require,'openssl') then
		stdnse.print_debug( 3, "Skipping %s script because OpenSSL is missing.", filename )
		return
	end

	local engine = brute.Engine:new(Driver, host, port)
	engine:setMaxThreads(thread_num)
	engine.options.script_name = SCRIPT_NAME
	status, result = engine:start()
	return result
end

