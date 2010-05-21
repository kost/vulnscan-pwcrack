description = [[
Tries to get Nessus login credentials by guessing usernames and passwords.
(using NTP protocol).

This uses the standard unpwdb username/password list.
]]

---
-- @output
-- PORT     STATE SERVICE
-- 1241/tcp open  nessus
-- | nessus-ntp-brute:  
-- |_  nessus: nessus

author = "Vlatko Kosturjak"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"auth", "intrusive"}

require "shortport"
require "stdnse"
require "unpwdb"
require "comm"

portrule = shortport.port_or_service(1241, "nessus")

local function login(host, port, user, pass)
	local status, err
	local res = ""

	local socket, response = comm.tryssl(host, port, "< NTP/1.2 >\n");
	if not socket then
		return false, "nessus-ntp-brute: Unable to open SSL connection or bad handshake"
	end

	if (string.match(response,"< NTP/1.2 >")) then
		stdnse.print_debug(3, "nessus-ntp-brute: Good handshake: %s", response)
	else	
		stdnse.print_debug(1, "nessus-ntp-brute: WARNING: Bad handshake: %s", response)
	end

	local status, err = socket:send(user.."\n")
	if (not(status)) then
		socket:close()
		return false, "nessus-ntp-brute: Couldn't send user: " .. err
	end

	status, err = socket:send(pass.."\n")
	if (not(status)) then
		socket:close()
		return false, "nessus-ntp-brute: Couldn't send password: " .. err
	end

	-- Create a buffer and receive the first line
	local buffer = stdnse.make_buffer(socket, "\r?\n")
	local line = buffer()

	if (line == nil or string.match(line,"Bad login")) then
		stdnse.print_debug(2, "nessus-ntp-brute: Bad login: %s/%s", user, pass)
		return true, false
	elseif (string.match(line,"SERVER <|>")) then
		stdnse.print_debug(1, "nessus-ntp-brute: Good login: %s/%s", user, pass)
		return true, true
	else
		stdnse.print_debug(1, "nessus-ntp-brute: WARNING: Unhandled response: %s", line)
	end

	socket:close()
	return false, "nessus-ntp-brute: Login didn't return a proper response"
end

local function go(host, port)
	local status, err
	local result
	local authcombinations = { 
		{user="nessus", password="nessus"},
		{user="ntp", password="ntp"}
	}

	-- Load accounts from unpwdb
	local usernames, username, passwords, password

	-- Load the usernames
	status, usernames = unpwdb.usernames()
	if(not(status)) then
		return false, "nessus-ntp-brute: Couldn't load username list: " .. usernames
	end

	-- Load the passwords
	status, passwords = unpwdb.passwords()
	if(not(status)) then
		return false, "nessus-ntp-brute: Couldn't load password list: " .. passwords
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

	stdnse.print_debug(1, "nessus-ntp-brute: Loaded %d username/password pairs", #authcombinations)

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

