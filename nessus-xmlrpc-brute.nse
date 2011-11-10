description=[[
Performs brute force password auditing against a Nessus vulnerability scanning daemon using the XMLRPC protocol.
]]

---
-- @output
-- PORT     STATE SERVICE       REASON  VERSION
-- 8834/tcp open  ssl/nessuswww syn-ack
-- | nessus-xmlrpc-brute: 
-- |   Accounts
-- |     nessus:nessus - Valid credentials
-- |   Statistics
-- |_    Performed 6 guesses in 1 seconds, average tps: 6

-- @args nessus-ntp-brute.threads sets the number of threads. Default: 4

author = "Vlatko Kosturjak"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"intrusive", "brute"}

require "shortport"
require "brute"
require "comm"
require "stdnse"

portrule = shortport.port_or_service(8834, "nessuswww", "tcp")

local DEFAULT_THREAD_NUM = 4

Driver = 
{
	new = function (self, host, port)
		local o = { host = host, port = port }
		setmetatable (o,self)
		self.__index = self
		return o
	end,

	connect = function ( self )
		return true	
	end,

	login = function( self, username, password )
		local status, err
		local res = ""

		local postdata="login="..username.."&password="..password

		--status, statusline, header, bod
		local req = http.post( self.host, self.port, '/login', nil, nil, postdata )

		if (not(req["status"])) then
			stdnse.print_debug(2, "Couldn't send/receive HTTPS request")
			return false, brute.Error:new( "Couldn't send/receive HTTPS request" ) 
		end

		body = req["body"]
		stdnse.print_debug(2, "nessus-xmlrpc-brute: Body login: %s", body)

		if (not body == nil) then
			stdnse.print_debug(2, "nessus-xmlrpc-brute: Bad login: %s", body)
			return false, brute.Error:new( "Bad login" )
		end

		if (body == nil or string.match(body,"<contents>Invalid login</contents>")) then
			stdnse.print_debug(2, "nessus-xmlrpc-brute: Bad login: %s/%s", user, pass)
			return false, brute.Error:new( "Bad login" )
		elseif (string.match(body,"<status>OK</status>")) then
			stdnse.print_debug(1, "nessus-xmlrpc-brute: Good login: %s/%s", username, password)
			return true, brute.Account:new(username, password, creds.State.VALID)
		end

		stdnse.print_debug(1, "nessus-xmlrpc-brute: WARNING: Unhandled response: %s", body)
		return false, brute.Error:new( "incorrect response from server" )
	end,

	disconnect = function( self )
		return true
	end,
}

action = function(host, port)
	local thread_num = stdnse.get_script_args("nessus-xmlrpc-brute.threads") or DEFAULT_THREAD_NUM
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
