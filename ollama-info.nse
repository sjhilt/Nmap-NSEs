local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local json = require "json"

--[[
Nmap Script: ollama-info

Description:
This script queries an OLLAMA server's `/api/tags` endpoint to retrieve a list of models.
If models are found, the script dynamically updates the service name to "ollama".

Usage:
nmap --script ollama-info -p <port> <target>

Default port:
The script targets port 11434 by default using the `shortport` library.

Dependencies:
- Requires the `json` NSE library for parsing JSON responses.
- Requires the `http` NSE library for HTTP requests.

Output Example:
PORT      STATE SERVICE
11434/tcp open  ollama
| ollama-info:
| Models Found:
| Name: qwen:0.5b-chat
|   Family: qwen2
|   Parameter Size: 620M
|   Quantization Level: Q4_0
|   Format: gguf
|   Digest: b5dc5e784f2a3ee1582373093acf69a2f4e2ac1710b253a001712b86a61f88bb
|   Size: 394998579
|   Modified At: 2024-04-09T11:00:08.391922682+08:00.

--]]

author = "Stephen Hilt"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

-- Port rule: Target port 11434 or services identified as HTTP
portrule = shortport.port_or_service(11434, "http")

action = function(host, port)
    -- Define the API endpoint path
    local path = "/api/tags"

    -- Make the HTTP GET request
    local response = http.get(host.ip, port.number, path)
    if not response then
        return string.format("Error: Could not connect to %s", url)
    end

    -- Check HTTP response status
    if response.status ~= 200 then
        return string.format("Error: Received HTTP %d from %s", response.status, url)
    end

    -- Parse the JSON response with the correct function signature
    local status, parsed_or_err = json.parse(response.body)
    if not status then
        return string.format("Error: Failed to parse JSON response: %s", parsed_or_err)
    end

    -- Extract the parsed object
    local parsed = parsed_or_err
    local output = {}

    

    -- Process the parsed JSON for models
    if type(parsed.models) == "table" then
        for _, model in ipairs(parsed.models) do
            stdnse.print_debug(1, "WHAT %s",  model.details.family)
            table.insert(output, string.format("Name: %s", model.name or "N/A"))
            if type(model.details) == "table" then
                table.insert(output, string.format("  Family: %s", model.details.family or "N/A"))
                table.insert(output, string.format("  Parameter Size: %s", model.details.parameter_size or "N/A"))
                table.insert(output, string.format("  Quantization Level: %s", model.details.quantization_level or "N/A"))
                table.insert(output, string.format("  Format: %s", model.details.format or "N/A"))
            end
            table.insert(output, string.format("  Digest: %s", model.digest or "N/A"))
            table.insert(output, string.format("  Size: %s", tostring(model.size) or "N/A"))
            table.insert(output, string.format("  Modified At: %s", model.modified_at or "N/A"))
            table.insert(output, "") -- Add a blank line between models
        end
    else
        table.insert(output, "No models found.")
    end

    -- Dynamically set service name if models are found
    if type(parsed.models) == "table" and #parsed.models > 0 then
        port.version.name = "Ollama"
        nmap.set_port_version(host, port)
        
    end

    return table.concat(output, "\n")
end
