local bin = require "bin"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[


]]

---
-- @usage
-- nmap --script atg-info -p 10001 <host>

author = "Stephen J. Hilt"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}


--
-- Function to define the portrule as per nmap standards
portrule = shortport.port_or_service(10001, "tcpwrapped", "tcp")
---
--  Function to set the nmap output for the host, if a valid ATG packet
--  is received then the output will show that the port as ATG  instead of
--  <code>tcpwrapped</code>
--
-- @param host Host that was passed in via nmap
-- @param port port that ATG is running on (Default TCP/10001)
function set_nmap(host, port)

  --set port Open
  port.state = "open"
  -- set version name to  Guardian AST
  port.version.name = " Guardian AST"
  nmap.set_port_version(host, port)
  nmap.set_port_state(host, port, "open")

end


---
--  Action Function that is used to run the NSE. This function will send the initial query to the
--  host and port that were passed in via nmap. The initial response is parsed to determine if host
--  is a ATG device. If it is then more actions are taken to gather extra information.
--
-- @param host Host that was scanned via nmap
-- @param port port that was scanned via nmap
action = function(host, port)

  -- create new socket
  local sock = nmap.new_socket()
  -- set timeout low in case we don't get a response
  sock:set_timeout(1000)
  -- query to pull the tank inventory
  local tank_inventory = bin.pack("H", "014932303130300a")
  -- Connect to the remote host
  local constatus, conerr = sock:connect(host, port)
  if not constatus then
    stdnse.debug1(
      'Error establishing a TCP connection for %s - %s', host, conerr
      )
    return nil
  end
 -- send query to inventory the tanks
 local sendstatus, senderr = sock:send(tank_inventory)
  if not sendstatus then
    stdnse.debug1(
      'Error sending ATG request to %s:%d - %s',
      host.ip, port.number,  senderr
      )
    return nil
  end
  -- receive the response for parseing
  local rcvstatus, response = sock:receive_bytes(1024)
  if(rcvstatus == false) then
    stdnse.debug1( "Receive error: %s", response)
    return nil
  end 
  -- if the response was timeout, then we will return that we had a timeout 
  --(for now add more addresses later)
  if (response == "TIMEOUT" or response == "EOF") then
    sock:close()
    return "TIMEOUT: No response from query"
  end
  -- if the first byte is 0x01 then likely the response is an ATG
  if(string.byte(response,1) == 0x01) then
    local inventory_output = string.sub(response,2,-2)
    set_nmap(host, port)
    sock:close()
    return inventory_output
  end
end
