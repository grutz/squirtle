#!/usr/bin/env ruby

# Squirtle's NTLM Functions class
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

require 'base64'

module NTLMFUNCS
	
		# NTLMSSP Message Flags 
		NEGOTIATE_UNICODE     = 0x00000001  # Only set if Type 1 contains it - this or oem, not both
		NEGOTIATE_OEM         = 0x00000002  # Only set if Type 1 contains it - this or unicode, not both
		REQUEST_TARGET        = 0x00000004  # If set in Type 1, must return domain or server
		NEGOTIATE_SIGN        = 0x00000010  # Session signature required
		NEGOTIATE_SEAL        = 0x00000020  # Session seal required
		NEGOTIATE_LMKEY       = 0x00000080  # LM Session Key should be used for signing and sealing
		NEGOTIATE_NTLM        = 0x00000200  # NTLM auth is supported
		NEGOTIATE_ANONYMOUS   = 0x00000800  # Anonymous context used
		NEGOTIATE_DOMAIN      = 0x00001000  # Sent in Type1, client gives domain info
		NEGOTIATE_WORKSTATION = 0x00002000  # Sent in Type1, client gives workstation info
		NEGOTIATE_LOCAL_CALL  = 0x00004000  # Server and client are on same machine
		NEGOTIATE_ALWAYS_SIGN = 0x00008000  # Add signatures to packets
		TARGET_TYPE_DOMAIN    = 0x00010000  # If REQUEST_TARGET, we're adding the domain name
		TARGET_TYPE_SERVER    = 0x00020000  # If REQUEST_TARGET, we're adding the server name
		TARGET_TYPE_SHARE     = 0x00040000  # Supposed to denote "a share" but for a webserver?
		NEGOTIATE_NTLM2_KEY   = 0x00080000  # NTLMv2 Signature and Key exchanges
		NEGOTIATE_TARGET_INFO = 0x00800000  # Server set when sending Target Information Block
		NEGOTIATE_128         = 0x20000000  # 128-bit encryption supported
		NEGOTIATE_KEY_EXCH    = 0x40000000  # Client will supply encrypted master key in Session Key field of Type3 msg
		NEGOTIATE_56          = 0x80000000  # 56-bit encryption supported

		#
		# convert string to unicode
		#
		def self.to_unicode(str='')
			return str.unpack('C*').pack('v*')
		end

		#
		# Process Type 3 NTLM Message (in Base64)
		#
		def self.process_type3_message(message)
			decode = Base64.decode64(message.strip)
			type = decode[8]
			if (type == 3)
				domoff = decode[32]	 # domain offset
				domlen = decode[28]	 # domain length
				useroff = decode[40] # username offset
				userlen = decode[36] # username length
				hostoff = decode[48] # hostname offset
				hostlen = decode[44] # hostname length
				lmoff = decode[16]	 # LM hash offset
				lmlen = decode[12]	 # LM hash length
				ntoff = decode[24]	 # NT hash offset
				ntlen = decode[20]	 # NT hash length

				domain = decode[domoff..domoff+domlen-1]
				user = decode[useroff..useroff+userlen-1]
				host = decode[hostoff..hostoff+hostlen-1]
				lm = decode[lmoff..lmoff+lmlen-1].unpack("H*")
				nt = decode[ntoff..ntoff+ntlen-1].unpack("H*")

				return domain, user, host, lm, nt
			else
				return "", "", "", "", ""
			end
		end

		#	 
		# Process Type 1 NTLM Messages, return a Base64 Type 2 Message
		#
		def self.process_type1_message(message, nonce = "\x11\x22\x33\x44\x55\x66\x77\x88", win_domain = 'DOMAIN', 
						win_name = 'SERVER', dns_name = 'server', dns_domain = 'example.com', downgrade = true)

			dns_name = to_unicode(dns_name + "." + dns_domain)
			win_domain = to_unicode(win_domain)
			dns_domain = to_unicode(dns_domain)
			win_name = to_unicode(win_name)
			decode = Base64.decode64(message.strip)

			type = decode[8]

			if (type == 1)
				# A type 1 message has been received, lets build a type 2 message response

				reqflags = decode[12..15]
				reqflags = Integer("0x" + reqflags.unpack("h8").to_s.reverse)

				if (reqflags & REQUEST_TARGET) == REQUEST_TARGET

					if (downgrade)
						# At this time NTLMv2 and signing requirements are not supported
						if (reqflags & NEGOTIATE_NTLM2_KEY) == NEGOTIATE_NTLM2_KEY
							reqflags = reqflags - NEGOTIATE_NTLM2_KEY
						end
						if (reqflags & NEGOTIATE_ALWAYS_SIGN) == NEGOTIATE_ALWAYS_SIGN
							reqflags = reqflags - NEGOTIATE_ALWAYS_SIGN
						end				
					end

					flags = reqflags + TARGET_TYPE_DOMAIN + TARGET_TYPE_SERVER				
					tid = true

					tidoffset = 48 + win_domain.length
					tidbuff = 
						[2].pack('v') +				# tid type, win domain
						[win_domain.length].pack('v') +
						win_domain +
						[1].pack('v') +				# tid type, server name
						[win_name.length].pack('v') +
						win_name +
						[4].pack('v')	+			 # tid type, domain name
						[dns_domain.length].pack('v') +
						dns_domain +
						[3].pack('v')	+			# tid type, dns_name
						[dns_name.length].pack('v') +
						dns_name
				else
					flags = NEGOTIATE_UNICODE + NEGOTIATE_NTLM
					tid = false
				end

				type2msg = "NTLMSSP\0" + # protocol, 8 bytes
					   "\x02\x00\x00\x00"		# type, 4 bytes

				if (tid)
					type2msg +=	# Target security info, 8 bytes. Filled if REQUEST_TARGET
					[win_domain.length].pack('v') +	 # Length, 2 bytes
					[win_domain.length].pack('v')	 # Allocated space, 2 bytes
				end

				type2msg +="\x30\x00\x00\x00" + #		Offset, 4 bytes
					 [flags].pack('V') +	# flags, 4 bytes
					 nonce +		# the nonce, 8 bytes
				 	 "\x00" * 8		# Context (all 0s), 8 bytes

				if (tid)
					type2msg +=		# Target information security buffer. Filled if REQUEST_TARGET
						[tidbuff.length].pack('v') +	# Length, 2 bytes
						[tidbuff.length].pack('v') +	# Allocated space, 2 bytes
						[tidoffset].pack('V') +		# Offset, 4 bytes (usually \x48 + length of win_domain)
						win_domain +			# Target name data (domain in unicode if REQUEST_UNICODE)
										# Target information data
						tidbuff +			#	Type, 2 bytes
										#	Length, 2 bytes
										#	Data (in unicode if REQUEST_UNICODE)
						"\x00\x00\x00\x00"		# Terminator, 4 bytes, all \x00
				end

				type2msg = Base64.encode64(type2msg).delete("\n") # base64 encode and remove the returns
			else
				# This is not a Type2 message
				type2msg = ""
			end

			return type2msg
		end

		#
		# Downgrading Type messages to LMv1/NTLMv1 and removing signing
		#
		def self.downgrade_type_message(message)
			decode = Base64.decode64(message.strip)

			type = decode[8]

			if (type > 0 and type < 4)
				reqflags = decode[12..15] if (type == 1 or type == 3)
				reqflags = decode[20..23] if (type == 2)
				reqflags = Integer("0x" + reqflags.unpack("h8").to_s.reverse)

				# Remove NEGOTIATE_NTLMV2_KEY and NEGOTIATE_ALWAYS_SIGN, this lowers the negotiation
				# down to LMv1/NTLMv1.
				if (reqflags & NEGOTIATE_NTLM2_KEY) == NEGOTIATE_NTLM2_KEY
					reqflags = reqflags - NEGOTIATE_NTLM2_KEY
				end
				if (reqflags & NEGOTIATE_ALWAYS_SIGN) == NEGOTIATE_ALWAYS_SIGN
					reqflags = reqflags - NEGOTIATE_ALWAYS_SIGN
				end				

				# Return the flags back to the decode so we can base64 it again
				flags = reqflags.to_s(16)
				0.upto(8) do |idx|
				  if (idx > flags.length)
				    flags.insert(0, "0")
				  end
				end

				idx = 0
				0.upto(3) do |cnt|
					if (type == 2)
						decode[23-cnt] = Integer("0x" + flags[idx .. idx + 1])
					else
						decode[15-cnt] = Integer("0x" + flags[idx .. idx + 1])
					end
					idx += 2
				end

			end
			return Base64.encode64(decode).delete("\n") # base64 encode and remove the returns 
		end

		#	 
		# Create a Base64 Type 2 Message from user-supplied data, not a Type 1 request
		#
		def self.create_type2_message(reqflags = "\x00\x00\x00\x00", nonce = "\x11\x22\x33\x44\x55\x66\x77\x88", win_domain = 'DOMAIN', 
						win_name = 'SERVER', dns_name = 'server', dns_domain = 'example.com', downgrade = true)

			dns_name = to_unicode(dns_name + "." + dns_domain)
			win_domain = to_unicode(win_domain)
			dns_domain = to_unicode(dns_domain)
			win_name = to_unicode(win_name)
			reqflags = Integer("0x" + reqflags.unpack("h8").to_s.reverse)

			if (reqflags & REQUEST_TARGET) == REQUEST_TARGET

					if (downgrade)
						# Remove NTLMv2 and Signing messages
						if (reqflags & NEGOTIATE_NTLM2_KEY) == NEGOTIATE_NTLM2_KEY
							reqflags = reqflags - NEGOTIATE_NTLM2_KEY
						end
						if (reqflags & NEGOTIATE_ALWAYS_SIGN) == NEGOTIATE_ALWAYS_SIGN
							reqflags = reqflags - NEGOTIATE_ALWAYS_SIGN
						end				
					end

					flags = reqflags + TARGET_TYPE_DOMAIN + TARGET_TYPE_SERVER				
					tid = true

					tidoffset = 48 + win_domain.length
					tidbuff = 
						[2].pack('v') +				# tid type, win domain
						[win_domain.length].pack('v') +
						win_domain +
						[1].pack('v') +				# tid type, server name
						[win_name.length].pack('v') +
						win_name +
						[4].pack('v')	+			 # tid type, domain name
						[dns_domain.length].pack('v') +
						dns_domain +
						[3].pack('v')	+			# tid type, dns_name
						[dns_name.length].pack('v') +
						dns_name
			else
				flags = NEGOTIATE_UNICODE + NEGOTIATE_NTLM
				tid = false
			end

			type2msg = "NTLMSSP\0" + # protocol, 8 bytes
				   "\x02\x00\x00\x00"		# type, 4 bytes

			if (tid)
				type2msg +=	# Target security info, 8 bytes. Filled if REQUEST_TARGET
				[win_domain.length].pack('v') +	 # Length, 2 bytes
				[win_domain.length].pack('v')	 # Allocated space, 2 bytes
			end

			type2msg +="\x30\x00\x00\x00" + #		Offset, 4 bytes
				 [flags].pack('V') +	# flags, 4 bytes
				 nonce +		# the nonce, 8 bytes
			 	 "\x00" * 8		# Context (all 0s), 8 bytes

			if (tid)
				type2msg +=		# Target information security buffer. Filled if REQUEST_TARGET
					[tidbuff.length].pack('v') +	# Length, 2 bytes
					[tidbuff.length].pack('v') +	# Allocated space, 2 bytes
					[tidoffset].pack('V') +		# Offset, 4 bytes (usually \x48 + length of win_domain)
					win_domain +			# Target name data (domain in unicode if REQUEST_UNICODE)
									# Target information data
					tidbuff +			#	Type, 2 bytes
									#	Length, 2 bytes
									#	Data (in unicode if REQUEST_UNICODE)
					"\x00\x00\x00\x00"		# Terminator, 4 bytes, all \x00
			end

			return Base64.encode64(type2msg).delete("\n") # base64 encode and remove the returns

		end

end

