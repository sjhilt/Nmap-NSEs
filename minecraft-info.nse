local nmap   = require "nmap"
local comm   = require "comm"
local stdnse = require "stdnse"
local shortport = require "shortport"
local unicode = require "unicode"

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

author = "Stephen Hilt"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe","discovery"}

portrule = shortport.port_or_service(25565, "minecraft")

--
-- Function to split a string based on a separator
-- 
-- @param sep A separator to split the string upon
function string:split(sep)
  local sep, fields = sep or ":", {}
  local pattern = string.format("([^%s]+)", sep)
  self:gsub(pattern, function(c) fields[#fields+1] = c end)
  return fields
end

---
--  Action Function that is used to run the NSE. This function will send the initial query to the
--  host and port that were passed in via nmap. The initial response is parsed to determine if host
--  is a Minecraft server. 
--
-- @param host Host that was scanned via nmap
-- @param port port that was scanned via nmap
action = function(host, port)
  -- this is a hand shake packet that is calculated based off the length of the IP address
  local init_packet = bin.pack("H", tonumber(string.len(host["ip"],16)))
  -- Packet built to query the information about the Minecraft Server
  local ip_packet = bin.pack("HCA>SH", "002f" ,string.len(host["ip"]) , tostring(host["ip"]) , port["number"], "010100")
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
  
  sock:send(init_packet)
  sock:send(ip_packet)
  
  -- receive response
  local rcvstatus, response = sock:receive()
  if(rcvstatus == false) then
    stdnse.debug1("Receive error: %s", response)
    return nil
  end
  -- close socket before paresing 
  sock:close()
  -- split the fields in response based off comma
  local fields = response:split(",")
  -- first field is description field
  local desc = fields[1]:split(":")
  -- store description in output table
  output["Description"] = desc[2]:gsub("\"", "")
  -- parse the maximum number of players for this server
  local max_player = fields[2]:split("{") 
  max_player = max_player[2]:split(":")
  output["Max Players"] = max_player[2]:gsub("\"", "") 
  -- parse the number of players currently online
  local online_player = fields[3]:split("}")
  online_player = online_player[1]:split(":")
  output["Online Players"] = online_player[2]:gsub("\"", "")
  -- parse the version number
  local version = fields[4]:split("{")
  version = version[2]:gsub("\"", "")
  version = version:split(":")
  -- if version number is in field 3, then we have more information in packet
  if (version[1] ~= "version") then
    version = fields[6]:gsub("\"", "")
	version = version:split(":")
	version[2] = version[3]
  end
  output["Version"] = version[2]
  
  -- parse the protocol version number
  local protocol = fields[5]:split("}")
  protocol = protocol[1]:split(":")
  -- if protocol isn't in field 5, then we had more information in packet
  if( protocol[1] ~= "protocol") then
    protocol = fields[7]:gsub("\"", "")
	protocol = protocol:split(":")
  end
  output["Protocol"]= protocol[2]:gsub("}", "")
  -- return the output table
  return output
end
