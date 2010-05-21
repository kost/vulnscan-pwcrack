description = [[
Tries to get Nessus login credentials by guessing usernames and passwords.
(using XMLRPC protocol available on Nessus 4.2+).

This uses the standard unpwdb username/password list.

Make sure to run service detection as SSL is often required for this 
service.
]]

---
-- @output
-- PORT     STATE SERVICE  REASON  VERSION
-- 8834/tcp open  ssl/jdwp syn-ack
-- | nessus-xmlrpc-brute:  
-- |_  nessus: nessus

author = "Vlatko Kosturjak"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"auth", "intrusive"}

require "shortport"
require "stdnse"
require "http"
require "unpwdb"

-- nessus XMLRPC interface is identified as jdwp, that is bug and
-- and should be fixed in nmap service detection
portrule = shortport.port_or_service(8834, "jdwp")

local function login(host, port, user, pass)
	local status, err
	local res = ""

	local postdata="login="..user.."&password="..pass
	local postdat = {
		{login = user }, 
		{password = pass }
	}

	--status, statusline, header, bod
	local req = http.post( host, port, '/login', nil, nil, postdata )

	if (not(req["status"])) then
		return false, "nessus-xmlrpc-brute: Couldn't send/receive HTTPS request: " .. err
	end

	body = req["body"]

	if (not body == nil) then
		stdnse.print_debug(2, "nessus-xmlrpc-brute: Bad login: %s", body)
	end

	if (body == nil or string.match(body,"<contents>Invalid login</contents>")) then
		stdnse.print_debug(2, "nessus-xmlrpc-brute: Bad login: %s/%s", user, pass)
		return true, false
	elseif (string.match(body,"<status>OK</status>")) then
		stdnse.print_debug(1, "nessus-xmlrpc-brute: Good login: %s/%s", user, pass)
		return true, true
	else
		stdnse.print_debug(1, "nessus-xmlrpc-brute: WARNING: Unhandled response: %s", body)
	end

	return false, "nessus-xmlrpc-brute: Login didn't return a proper response"
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
		return false, "nessus-xmlrpc-brute: Couldn't load username list: " .. usernames
	end

	-- Load the passwords
	status, passwords = unpwdb.passwords()
	if(not(status)) then
		return false, "nessus-xmlrpc-brute: Couldn't load password list: " .. passwords
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

	stdnse.print_debug(1, "nessus-xmlrpc-brute: Loaded %d username/password pairs", #authcombinations)

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

