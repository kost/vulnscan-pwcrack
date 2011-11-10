description=[[
Performs brute force password auditing against a Metasploit RPC server using the XMLRPC protocol.
]]

---
-- @usage
-- nmap --script metasploit-xmlrpc-brute -p 55553 <host>
--
-- @output
-- PORT      STATE SERVICE               REASON  VERSION
-- 55553/tcp open  ssl/metasploit-xmlrpc syn-ack
-- | metasploit-xmlrpc-brute: 
-- |   Accounts
-- |     msf:msf - Valid credentials
-- |   Statistics
-- |_    Performed 4 guesses in 1 seconds, average tps: 4
--
-- @args metasploit-xmlrpc-brute.threads sets the number of threads. Default: 4

author = "Vlatko Kosturjak"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

require "shortport"
require "brute"
require "comm"
require "stdnse"

portrule = shortport.port_or_service(55553, "metasploit-xmlrpc", "tcp")

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
		local xmlreq='<?xml version="1.0" ?><methodCall><methodName>auth.login</methodName><params><param><value><string>'..username..'</string></value></param><param><value><string>'..password.."</string></value></param></params></methodCall>\n"..string.char(0)
		local status, err = self.socket:send(xmlreq)

		if ( not ( status ) ) then
			local err = brute.Error:new( "Unable to send handshake" )
			err:setAbort(true)
			return false, err
		end


		-- Create a buffer and receive the first line
		-- status, response = self.socket:receive()
		local response 
		status, response = self.socket:receive_buf("\r?\n", false)

		if (response == nil or string.match(response,"<name>faultString</name><value><string>authentication error</string>")) then
			stdnse.print_debug(2, "metasploit-xmlrpc-brute: Bad login: %s/%s", username, password)
			return false, brute.Error:new( "Bad login" )
		elseif (string.match(response,"<name>result</name><value><string>success</string></value>")) then
				
			stdnse.print_debug(1, "metasploit-xmlrpc-brute: Good login: %s/%s", username, password)
			return true, brute.Account:new(username, password, creds.State.VALID)
		else
			stdnse.print_debug(1, "metasploit-xmlrpc-brute: WARNING: Unhandled response: %s", line)
			return false, brute.Error:new( "unhandled response" )
		end

		return false, brute.Error:new( "incorrect response from server" )
	end,

	disconnect = function( self )
		self.socket:close()
	end,
}

action = function(host, port)
	local thread_num = stdnse.get_script_args("metasploit-xmlrpc-brute.threads") or DEFAULT_THREAD_NUM
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

