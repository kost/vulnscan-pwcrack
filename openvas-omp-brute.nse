description = [[
Tries to get OpenVAS login credentials by guessing usernames and passwords.
(using OMP protocol).

This uses the standard unpwdb username/password list.
]]

---
-- @output
-- PORT     STATE SERVICE     REASON  VERSION
-- 9391/tcp open  ssl/openvas syn-ack OpenVAS server
-- | openvas-omp-brute:  
-- |_  openvas: openvas

author = "Vlatko Kosturjak"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"auth", "intrusive"}

require "shortport"
require "stdnse"
require "unpwdb"
require "comm"

portrule = shortport.port_or_service({9390,9391} , "openvas")

local function login(host, port, user, pass)
	local status, err
	local res = ""
	local xmlreq = "<authenticate><credentials><username>"..user.."</username><password>"..pass.."</password></credentials></authenticate><HELP/>\r\n"
	local socket, response = comm.tryssl(host, port, xmlreq)
	if not socket then
		return false, "openvas-omp-brute: Unable to open SSL connection or bad handshake"
	end

	if (string.match(response,"Authentication failed")) then
		stdnse.print_debug(2, "openvas-omp-brute: Bad login: %s/%s", user, pass)
		socket:close()
		return true, false
	elseif (string.match(response,"<authenticate_response.*status=\"200\"")) then
		stdnse.print_debug(1, "openvas-omp-brute: Good login: %s/%s", user, pass)
		socket:close()
		return true, true
	else	
		stdnse.print_debug(1, "openvas-omp-brute: WARNING: Unhandled response: %s", line)
	end

	socket:close()
	return false, "openvas-omp-brute: Login didn't return a proper response"
end

local function go(host, port)
	local status, err
	local result
	local authcombinations = { 
		{user="openvas", password="openvas"},
		{user="otp", password="otp"}
	}

	-- Load accounts from unpwdb
	local usernames, username, passwords, password

	-- Load the usernames
	status, usernames = unpwdb.usernames()
	if(not(status)) then
		return false, "openvas-omp-brute: Couldn't load username list: " .. usernames
	end

	-- Load the passwords
	status, passwords = unpwdb.passwords()
	if(not(status)) then
		return false, "openvas-omp-brute: Couldn't load password list: " .. passwords
	end

	-- Add the passwords to the authcombinations table
	password = passwords()
	while (password) do
		username = usernames()
		while(username) do
			table.insert(authcombinations, {user=username, password=password})
			username = usernames()
		end
		usernames('reset')
		password = passwords()
	end

	stdnse.print_debug(1, "openvas-omp-brute: Loaded %d username/password pairs", #authcombinations)

	local results = {}
	for _, combination in ipairs(authcombinations) do


		-- Attempt a login
		status, result = login(host, port, combination.user, combination.password)

		-- Check for an error
		if(not(status)) then
			return false, result
		end

		-- Check for a success
		if(status and result) then
			table.insert(results, combination)
		end
	end


	return true, results
end

action = function(host, port)
	if not pcall(require,'openssl') then
		stdnse.print_debug( 3, "Skipping %s script because OpenSSL is missing.", filename )
		return
	end

	local response = {}
	local status, results = go(host, port)

	if(not(status)) then
		return stdnse.format_output(false, results)
	end

	if(#results == 0) then
		return stdnse.format_output(false, "No accounts found")
	end

	for i, v in ipairs(results) do
		table.insert(response, string.format("%s: %s\n", v.user, v.password))
	end

	return stdnse.format_output(true, response)
end

