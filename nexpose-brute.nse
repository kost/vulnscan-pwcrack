description = [[
Tries to get NeXpose login credentials by guessing usernames and passwords.
(using API 1.1 protocol).

This uses the standard unpwdb username/password list.
]]

---
-- @output
-- PORT     STATE SERVICE     REASON  VERSION
-- 3780/tcp open  ssl/unknown syn-ack
-- | nexpose-brute:  
-- |_  nxadmin: nxadmin

author = "Vlatko Kosturjak"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"auth", "intrusive"}

require "shortport"
require "stdnse"
require "http"
require "unpwdb"

portrule = shortport.port_or_service(3780, "nexpose")

local function login(host, port, user, pass)
	local status, err
	local res = ""
	local header = { ["Content-Type"] ="text/xml" } 
	local options = { header = header }

	local postdata='<?xml version="1.0" encoding="UTF-8"?><LoginRequest sync-id="1" user-id="'..user..'" password="'..pass..'"></LoginRequest>'
	stdnse.print_debug(4, "nexpose-brute: Using: %s", postdata)

	local req = http.post( host, port, '/api/1.1/xml', options, nil, postdata )

	if (not(req["status"])) then
		return false, "nexpose-brute: Couldn't send/receive HTTPS request" 
	end

	body = req["body"]

	if (not body == nil) then
		stdnse.print_debug(2, "nexpose-brute: Bad login: %s", body)
	end

	if (body == nil or string.match(body,'<LoginResponse.*success="0"')) then
		stdnse.print_debug(2, "nexpose-brute: Bad login: %s/%s", user, pass)
		return true, false
	elseif (string.match(body,'<LoginResponse.*success="1"')) then
		stdnse.print_debug(1, "nexpose-brute: Good login: %s/%s", user, pass)
		return true, true
	else
		stdnse.print_debug(1, "nexpose-brute: WARNING: Unhandled response: %s", body)
	end

	return false, "nexpose-brute: Login didn't return a proper response"
end

local function go(host, port)
	local status, err
	local result
	local authcombinations = { 
		{user="nxadmin", password="nxadmin"},
		{user="nxadmin", password="nexpose"}
	}

	-- Load accounts from unpwdb
	local usernames, username, passwords, password

	-- Load the usernames
	status, usernames = unpwdb.usernames()
	if(not(status)) then
		return false, "nexpose-brute: Couldn't load username list: " .. usernames
	end

	-- Load the passwords
	status, passwords = unpwdb.passwords()
	if(not(status)) then
		return false, "nexpose-brute: Couldn't load password list: " .. passwords
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

	stdnse.print_debug(1, "nexpose-brute: Loaded %d username/password pairs", #authcombinations)

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

