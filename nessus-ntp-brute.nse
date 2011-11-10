description=[[
Performs brute force password auditing against a Nessus vulnerability scanning daemon using the NTP 1.2 protocol.
]]

---
-- @output
-- PORT     STATE SERVICE    REASON  VERSION
-- 1241/tcp open  ssl/nessus syn-ack Nessus Daemon (NTP v1.2)
-- | nessus-ntp-brute: 
-- |   Accounts
-- |     nessus:nessus - Valid credentials
-- |   Statistics
-- |_    Performed 4 guesses in 4 seconds, average tps: 1
--
-- @args nessus-ntp-brute.threads sets the number of threads. Default: 4

author = "Vlatko Kosturjak"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"intrusive", "brute"}

require "shortport"
require "brute"
require "comm"
require "stdnse"

portrule = shortport.port_or_service(1241, "nessus", "tcp")

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
		self.socket = nmap.new_socket() 
		if ( not(self.socket:connect(self.host, self.port, "ssl")) ) then
			return false
		end
		return true	
	end,

	login = function( self, username, password )
		local status, err = self.socket:send("< NTP/1.2 >\n")

		if ( not ( status ) ) then
			local err = brute.Error:new( "Unable to send handshake" )
			err:setAbort(true)
			return false, err
		end

		local response 
		status, response = self.socket:receive_buf("\r?\n", false)
		if ( not(status) or response ~= "< NTP/1.2 >" ) then
			local err = brute.Error:new( "Bad handshake from server: "..response )
			err:setAbort(true)
			return false, err
		end

		status, err = self.socket:send(username.."\n")
		if ( not(status) ) then
			local err = brute.Error:new( "Couldn't send user: "..username )
			err:setAbort( true )
			return false, err
		end

		status, err = self.socket:send(password.."\n")
		if ( not(status) ) then
			local err = brute.Error:new( "Couldn't send password: "..password )
			err:setAbort( true )
			return false, err
		end

		-- Create a buffer and receive the first line
		status, line = self.socket:receive_buf("\r?\n", false)

		if (line == nil or string.match(line,"Bad login") or string.match(line,"ERROR")) then
			stdnse.print_debug(2, "nessus-ntp-brute: Bad login: %s/%s", username, password)
			return false, brute.Error:new( "Bad login" )
		elseif (string.match(line,"SERVER <|>")) then
				
			stdnse.print_debug(1, "nessus-ntp-brute: Good login: %s/%s", username, password)
			return true, brute.Account:new(username, password, creds.State.VALID)
		end

		stdnse.print_debug(1, "nessus-ntp-brute: WARNING: Unhandled response: %s", line)
		return false, brute.Error:new( "unhandled response" )
	end,

	disconnect = function( self )
		self.socket:close()
	end,
}

action = function(host, port)
	local thread_num = stdnse.get_script_args("nessus-ntp-brute.threads") or DEFAULT_THREAD_NUM
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

