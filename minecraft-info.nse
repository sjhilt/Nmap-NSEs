local bin = require "bin" 
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

author = "Stephen Hilt"
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
  -- use json output table to pack new table with just information we want to output
  output["Description"] = value["description"]
  output["Max Players"] = value["players"]["max"]
  output["Players Online"] = value["players"]["online"]
  output["Version"] = value["version"]["name"]
  output["Protocol"] = value["version"]["protocol"]

  return output
end
