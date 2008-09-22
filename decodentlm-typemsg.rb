#!/usr/bin/env ruby

# decodentlm-typemsg.rb - Decode NTLM Type Messages
require 'base64'
require 'sq_ntlmfuncs'

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

def showflags(reqflags)
	puts " - Negotiate Unicode set" if (reqflags & NEGOTIATE_UNICODE) == NEGOTIATE_UNICODE
	puts " - Negotiate OEM set" if (reqflags & NEGOTIATE_OEM) == NEGOTIATE_OEM
	puts " - Request Target set" if (reqflags & REQUEST_TARGET) == REQUEST_TARGET
	puts " - Negotiate Sign set" if (reqflags & NEGOTIATE_SIGN) == NEGOTIATE_SIGN
	puts " - Negotiate Seal set" if (reqflags & NEGOTIATE_SEAL) == NEGOTIATE_SEAL
	puts " - Negotiate LMKEY set" if (reqflags & NEGOTIATE_LMKEY) == NEGOTIATE_LMKEY
	puts " - Negotiate NTLM set" if (reqflags & NEGOTIATE_NTLM) == NEGOTIATE_NTLM
	puts " - Negotiate Anonymous set" if (reqflags & NEGOTIATE_ANONYMOUS) == NEGOTIATE_ANONYMOUS
	puts " - Negotiate Domain set" if (reqflags & NEGOTIATE_DOMAIN) == NEGOTIATE_DOMAIN
	puts " - Negotiate Workstation set" if (reqflags & NEGOTIATE_WORKSTATION) == NEGOTIATE_WORKSTATION
	puts " - Negotiate Local Call set" if (reqflags & NEGOTIATE_LOCAL_CALL) == NEGOTIATE_LOCAL_CALL
	puts " - Negotiate Always Sign set" if (reqflags & NEGOTIATE_ALWAYS_SIGN) == NEGOTIATE_ALWAYS_SIGN
	puts " - Negotiate Type Domain set" if (reqflags & TARGET_TYPE_DOMAIN) == TARGET_TYPE_DOMAIN
	puts " - Negotiate Type Server set" if (reqflags & TARGET_TYPE_SERVER) == TARGET_TYPE_SERVER
	puts " - Negotiate Type Share set" if (reqflags & TARGET_TYPE_SHARE) == TARGET_TYPE_SHARE
	puts " - Negotiate NTLMv2 set" if (reqflags & NEGOTIATE_NTLM2_KEY) == NEGOTIATE_NTLM2_KEY
	puts " - Negotiate Target Info set" if (reqflags & NEGOTIATE_TARGET_INFO) == NEGOTIATE_TARGET_INFO
	puts " - Negotiate 128 set" if (reqflags & NEGOTIATE_128) == NEGOTIATE_128
	puts " - Negotiate Key Exchange set" if (reqflags & NEGOTIATE_KEY_EXCH) == NEGOTIATE_KEY_EXCH
	puts " - Negotiate 56 set" if (reqflags & NEGOTIATE_56) == NEGOTIATE_56
end

def decode(message)
	decode = Base64.decode64(message.strip)
	type = decode[8]
	puts ".----------------."
	puts "| Type #{type} Message |----------------------------------------------------------]"
	puts "`----------------'"
	
	if (type > 0 and type < 4)
		reqflags = decode[12..15].reverse if (type == 1 or type == 3)
		reqflags = decode[20..23].reverse if (type == 2)
		puts "Flags: #{reqflags.unpack("H8").to_s} - #{reqflags.unpack('B*')}"
		reqflags = Integer("0x" + reqflags.unpack("H8").to_s)
		showflags(reqflags)
	end
	
	if (type == 2)
		challenge = decode[24..31]
		puts "\n.:[ Challenge: #{challenge.unpack("H*").to_s} ]:.\n\n"
		if (reqflags & REQUEST_TARGET) == REQUEST_TARGET
			tibtypes = [nil, "NetBIOS host", "NetBIOS Domain", "Server Name", "DNS Domain Name"]
			puts ".--------------------------."
			puts "| Target Information Block |------------------------------------------------]"
			puts "`--------------------------'"
			tiboff = decode[44]
			tiblen = decode[40]
			while (tiboff < tiblen)
				tibsubtype = decode[tiboff]
				tibsublen = decode[tiboff + 2]
				tibsubdata = decode[tiboff + 4, tibsublen]
				puts " - #{tibtypes[tibsubtype]}: #{tibsubdata.gsub(/\x00/, '')}"
				tiboff += tibsublen + 4
			end
		end
	end
	
	if (type == 3)
		(domain, user, host, lm, nt) = NTLMFUNCS.process_type3_message(message)	
		puts "#{user}/#{host}:#{domain}:#{lm}:#{nt}"
	end
end

msg = ARGV[0] || "TlRMTVNTUAABAAAABzIAAAYABgArAAAACwALACAAAABXT1JLU1RBVElPTkRPTUFJTg=="
#msg = "TlRMTVNTUAACAAAADAAMADAAAAAFgomgd8ot4MNgsDoAAAAAAAAAAIYAhgA8AAAAVwBJAE4ARABPAE0AAgAMAFcASQBOAEQATwBNAAEAHgBCAEEALQBJADAARwBCADYAQgBGAE0AWgAzAE0AVgAEABQAdwBpAG4AZABvAG0ALgBjAG8AbQADADQAYgBhAC0AaQAwAGcAYgA2AGIAZgBtAHoAMwBtAHYALgB3AGkAbgBkAG8AbQAuAGMAbwBtAAAAAAA="
#msg = "TlRMTVNTUAABAAAABzIAAAYABgArAAAACwALACAAAABXT1JLU1RBVElPTkRPTUFJTg=="
#msg = "TlRMTVNTUAACAAAADAAMADAAAAABAoEAASNFZ4mrze8AAAAAAAAAAGIAYgA8AAAARABPAE0AQQBJAE4AAgAMAEQATwBNAEEASQBOAAEADABTAEUAUgBWAEUAUgAEABQAZABvAG0AYQBpAG4ALgBjAG8AbQADACIAcwBlAHIAdgBlAHIALgBkAG8AbQBhAGkAbgAuAGMAbwBtAAAAAAA="
#msg = "TlRMTVNTUAACAAAADAAMADAAAAAFAoEAu+LqAGRSF+UAAAAAAAAAAIYAhgA8AAAAVwBJAE4ARABPAE0AAgAMAFcASQBOAEQATwBNAAEAHgBCAEEALQBJADAARwBCADYAQgBGAE0AWgAzAE0AVgAEABQAdwBpAG4AZABvAG0ALgBjAG8AbQADADQAYgBhAC0AaQAwAGcAYgA2AGIAZgBtAHoAMwBtAHYALgB3AGkAbgBkAG8AbQAuAGMAbwBtAAAAAAA="
#msg = "TlRMTVNTUAACAAAANjUxMjYyMAAAAAXCgaDmnZs/4M8UfKiVPgoAAAAAhgCGADwAAABXAEkATgBEAE8ATQACAAwAVwBJAE4ARABPAE0AAQAeAEIAQQAtAEkAMABHAEIANgBCAEYATQBaADMATQBWAAQAFAB3AGkAbgBkAG8AbQAuAGMAbwBtAAMANABiAGEALQBpADAAZwBiADYAYgBmAG0AegAzAG0AdgAuAHcAaQBuAGQAbwBtAC4AYwBvAG0AAAAAAA=="

decode(msg)

