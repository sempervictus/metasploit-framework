# -*- coding: binary -*-
module Rex
module Proto
module DCERPC
class Authentication

require 'rex/proto/dcerpc/uuid'
require 'rex/proto/dcerpc/response'
require 'rex/text'

	def self.ntlmssp_verifier()
		buff =
		[ 
			1,
			"\xeb\x07\x82\x29\xaf\x5a\x89\x9e\x00\x00\x00\x00"
		].pack('Va*')
		return buff
	end
	
	def self.auth_buff(auth_type, auth_level, pad_length=0)
		buff =
                [
                        auth_type,      # 9: SPNEGO 10: NTLMSSP
                        auth_level,      # 2: Connect 5: PacketIntegrity
                        pad_length,      # Auth pad len
                        0,      # Auth rsrvd
                        0x6B8B4567, # Auth context id
                ].pack('CCCCV')

		return buff
	end

	def self.auth_ntlm_1(auth_type, auth_level, domain, name, ntlm_options)
		flags = Rex::Proto::NTLM::Utils.make_ntlm_flags(ntlm_options)
		if auth_type == 9
			ntlm_1 = Rex::Proto::NTLM::Utils.make_ntlmssp_secblob_init(domain, name, flags)
		else
			ntlm_1 = Rex::Proto::NTLM::Utils.make_ntlmssp_blob_init(domain, name, flags)
		end
		buff = self.auth_buff(auth_type, auth_level)

		return buff+ntlm_1, ntlm_1.length
	end

	def self.auth_ntlm_3(auth_type, auth_level, last_response, opts, ntlm_options)
		flags = Rex::Proto::NTLM::Utils.make_ntlm_flags(ntlm_options)
		start = last_response.raw.index("NTLMSSP")
                ntlmssp = last_response.raw[start..-1]
               	ntlm_2 = Rex::Proto::NTLM::Utils.parse_ntlm_type_2_blob(ntlmssp)

		resp_lm, resp_ntlm, client_challenge, ntlm_cli_challenge = Rex::Proto::NTLM::Utils.create_lm_ntlm_responses(
			opts[:user],
			opts[:password],
			ntlm_2[:challenge_key],
			opts[:domain],
			opts[:name],
			ntlm_2[:default_domain],
			ntlm_2[:dns_host_name],
			ntlm_2[:dns_domain_name],
			ntlm_2[:chall_MsvAvTimestamp],
			{}, #spnopt
			ntlm_options
		)

                enc_session_key = ''

		signing_key, enc_session_key, ntlmssp_flags = Rex::Proto::NTLM::Utils.create_session_key(
			flags,
			opts[:server_ntlmssp_flags],
			opts[:user],
			opts[:password],
			opts[:domain],
			ntlm_2[:challenge_key],
			client_challenge,
			ntlm_cli_challenge,
			ntlm_options
		)
		
		if auth_type == 9
			ntlm_3 = Rex::Proto::NTLM::Utils.make_ntlmssp_secblob_auth(
				opts[:domain],
				opts[:name],
				opts[:user],
				resp_lm,
				resp_ntlm,
				enc_session_key,
				flags)
		else
			ntlm_3 = Rex::Proto::NTLM::Utils.make_ntlmssp_blob_auth(
                                opts[:domain],
                                opts[:name],
                                opts[:user],
                                resp_lm,
                                resp_ntlm,
                                enc_session_key,
                                flags)
		end

		buff = self.auth_buff(auth_type, auth_level)
		return buff+ntlm_3, ntlm_3.length
	end

end
end
end
end
