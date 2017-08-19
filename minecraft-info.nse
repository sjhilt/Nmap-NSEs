local nmap   = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local json = require "json"

description = [[
This script will query a Minecraft server for some basic information about the host. 
The information that is queried is the Description, Maximum Number of Players, number of 
Online Players, Version number, and Protocol Number. This work was inspired by the results 
shown in Shodan for Minecraft Servers. 
]]
-- @usage
-- nmap --script minecraft-info.nse -p 25565 <host>
---
-- @output
-- Host script results:
-- | minecraft-info:
-- |   Description: A Minecraft Server
-- |   Max Players: 20
-- |   Online Players: 0
-- |   Version: 1.8
-- |_  Protocol: 47
---
-- @xmloutput
--<elem key="Description">A Minecraft Server</elem>
--<elem key="Max Players">20</elem>
--<elem key="Online Players">0</elem>
--<elem key="Version">1.8</elem>
--<elem key="Protocol">47</elem>
--<elem key="Login Status">Original Server</elem>

author = "Stephen Hilt & space1024"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe","discovery"}

portrule = shortport.port_or_service(25565, "minecraft")
---
--  Action Function that is used to run the NSE. This function will send the initial query to the
--  host and port that were passed in via nmap. The initial response is parsed to determine if host
--  is a Minecraft server. 
--
-- @param host Host that was scanned via nmap
-- @param port port that was scanned via nmap 
action = function(host, port)
  --http://wiki.vg/Protocol#Handshake
  -- handshake (0x00) packet is formed by~: ip(len) + protocol_vers + ip_len(2 bytes) + ip(string) + port(2 bytes) + next_state(1 = status, 2 = login) + code
  --currently using protocol 47 (1.8.x) but this haven't utility for status ¯\_(ツ)_/¯ 
  local stat_packet = bin.pack("HHCA>SH", tonumber(string.len(host["ip"],16)) ,"002f" ,string.len(host["ip"]) , tostring(host["ip"]) , port["number"], "010100")
  -- create output table
  local output = stdnse.output_table()
  -- create socket
  local sock = nmap.new_socket()
  
  -- connect to remote host
  local constatus, conerr = sock:connect(host, port)
  -- if not successful debug error message and return nil
  if not constatus then
    stdnse.debug1(
      'Error establishing a TCP connection for %s - %s', host, conerr
      )
    return nil
  end
  
  sock:send(stat_packet)
  
  -- receive response
  local rcvstatus, response = sock:receive()
  if(rcvstatus == false) then
    stdnse.debug1("Receive error: %s", response)
    return nil
  end
  -- get the length of the packet for a size offset
  local size = string.len(response)
  local pos = 1
  local test = nil
  -- while the charictar is not 0x7b({) get next char
  while (test ~= 0x7b) do
    pos, test =  bin.unpack("C", response, pos)
  end  
  -- set size offest to pos + 2
  size = size - pos + 2
  -- unpack a json string that contains descriptions
  local pos, json_string = bin.unpack("A" .. size, response, pos-1)
  -- some hosts have data, this is something that we could parse later, however
  -- to stop get the string I'll just split at favicon and use the first part
  -- of the string to only get the values before the favicon which contains
  -- the infromation we are going to parse later..
  if(string.find(json_string, "favicon") ~= nil) then
    json_string = stdnse.strsplit("favicon", json_string)
    json_string = json_string[1] .. "something\":{}}"
  end
  -- sometimes its modinfo that is causing the issue
  if(string.find(json_string, "modinfo") ~= nil) then
    json_string = stdnse.strsplit("modinfo", json_string)
    json_string = json_string[1] .. "something\":{}}"
  end
  -- convert string into json table
  local pos, value = json.parse(tostring(json_string))
  -- convert string into json table
  local pos, value = json.parse(tostring(json_string))
    -- close socket before parsing
  sock:close()
  
  --http://wiki.vg/Protocol_version_numbers
  local protocol_vers = tonumber(value["version"]["protocol"])
  local login_handshake = bin.pack("H>sCA>SH", tonumber(string.len(host["ip"],16)) ,protocol_vers ,string.len(host["ip"]) , tostring(host["ip"]) , port["number"], "02")
	--if you want you can do this in one line :)
	--http://wiki.vg/Protocol#Login_Start
	local username = "NmapBot" --change this if you need
	local packet_id = "00"
	local total_len = string.len(string.fromhex(packet_id)) + 1 + string.len(username)
	local login_packet = bin.pack("CHCA", total_len, packet_id, string.len(username), username)
	
	local sock = nmap.new_socket()
  
  -- connect to remote host (again...)
  local constatus, conerr = sock:connect(host, port)
  -- if not successful debug error message and return nil
  if not constatus then
    stdnse.debug1(
      'Error establishing a TCP connection for %s - %s', host, conerr
      )
    return nil
  end
  
   
	sock:send(login_handshake)
	  sock:send(login_packet)
	  
	  --yea, i'd like create new variables :D
  local rcvstatus, response2 = sock:receive()
  if(rcvstatus == false) then
    stdnse.debug1("Receive error: %s", response2)
    return nil
  end
  local size = string.len(response2)
  --check the response from the server
  --http://wiki.vg/Protocol#Login
  local resp_status
    if (string.sub(response2,2,2) == "\x00") then
		if size < 3 then
			resp_status = "Error."
		else
			resp_status = tostring("%s%s","Error ", string.sub(response2,3))
		end
    elseif (string.sub(response2,2,2) == "\x01") then
	resp_status = "Original server"
	elseif (string.sub(response2,2,2) == "\x02") then
	resp_status = "Cracked server"
	elseif (response2 == "EOF") then
	resp_status = "Null Response"
    else
	resp_status = tostring("Unknown packet id ", tonumber(string.sub(response2,2,2)))
    end
  
  -- use json output table to pack new table with just information we want to output
  output["Description"] = value["description"]
  output["Max Players"] = value["players"]["max"]
  output["Players Online"] = value["players"]["online"]
  output["Version"] = value["version"]["name"]
  output["Protocol"] = value["version"]["protocol"]
  output["Login Status"] = resp_status
  --output["Login Response"] = response2  --uncomment to view response returned by the server (login)
  return output
end
--i need this :/
function string.fromhex(str)
str = string.format("%s",str)
    return (str:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end
