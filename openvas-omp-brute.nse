description=[[
Performs brute force password auditing against a OpenVAS vulnerability scanner daemon using the OMP protocol.
]]

---
-- @output
-- PORT     STATE SERVICE    REASON  VERSION
-- 9390/tcp open  ssl/openvas syn-ack 
-- | openvas-omp-brute: 
-- |   Accounts
-- |     openvas:openvas - Valid credentials
-- |   Statistics
-- |_    Performed 4 guesses in 4 seconds, average tps: 1
--
-- @args openvas-omp-brute.threads sets the number of threads. Default: 4

author = "Vlatko Kosturjak"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"intrusive", "brute"}

require "shortport"
require "brute"
require "comm"
require "stdnse"

portrule = shortport.port_or_service({9390,9391}, "openvas", "tcp")

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
		local status, err
		local res = ""
		local xmlreq = "<authenticate><credentials><username>"..username.."</username><password>"..password.."</password></credentials></authenticate><HELP/>\r\n"
		local response

		status, err = self.socket:send(xmlreq)
		if ( not ( status ) ) then
			local err = brute.Error:new( "Unable to send request" )
			err:setAbort(true)
			return false, err
		end

		status, response = self.socket:receive_buf("\r?\n", false)	
		if (string.match(response,"Authentication failed")) then
			stdnse.print_debug(2, "openvas-omp-brute: Bad login: %s/%s", username, password)
			return false, brute.Error:new( "Bad login" )
		elseif (string.match(response,"<authenticate_response.*status=\"200\"")) then
			stdnse.print_debug(1, "openvas-omp-brute: Good login: %s/%s", username, password)
			return true, brute.Account:new(username, password, creds.State.VALID)
		end	
		stdnse.print_debug(1, "openvas-omp-brute: WARNING: Unhandled response: %s", response)
		return false, brute.Error:new( "unhandled response" )
	end,

	disconnect = function( self )
		self.socket:close()
	end,
}

action = function(host, port)
	local thread_num = stdnse.get_script_args("openvas-omp-brute.threads") or DEFAULT_THREAD_NUM
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

