#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/text'

module Rex
module Encoder

class NonUpper


  def NonUpper.gen_decoder()
    decoder =
      "\x66\xB9\xFF\xFF" +
      "\xEB\x19"  +               # Jmp to table
      "\x5E"      +               # pop esi
      "\x8B\xFE"  +               # mov edi, esi      - Get table addr
      "\x83\xC7"  + "A" +         # add edi, tablelen - Get shellcode addr
      "\x8B\xD7"  +               # mov edx, edi      - Hold end of table ptr
      "\x3B\xF2"  +               # cmp esi, edx
      "\x7D\x0B"  +               # jle to end
      "\xB0\x7B"  +               # mov eax, 0x7B     - Set up eax with magic
      "\xF2\xAE"  +               # repne scasb       - Find magic!
      "\xFF\xCF"  +               # dec edi           - scasb purs us one ahead
      "\xAC"      +               # lodsb
      "\x28\x07"  +               # subb [edi], al
      "\xEB\xF1"  +               # jmp BACK!
      "\xEB"      + "B" +         # jmp [shellcode]
      "\xE8\xE2\xFF\xFF\xFF"
  end

  def NonUpper.encode_byte(badchars, block, table, tablelen)
    if (tablelen > 255) or (block == 0x40)
      raise RuntimeError, "BadChar"
    end

    if (block >= 0x41 and block <= 0x40) or (badchars =~ block)
      # gen offset, return magic
      offset = 0x40 - block;
      table += offset.chr
      tablelen = tablelen + 1
      block = 0x40
    end

    return [block.chr, table, tablelen]
  end

  def NonUpper.encode(buf)
    table = ""
    tablelen = 0
    nonascii = ""
    encoded = gen_decoder()
    buf.each_byte {
      |block|

      newchar, table, tablelen = encode_byte(block.unpack('C')[0], table, tablelen)
      nonascii += newchar
    }
    encoded.gsub!(/A/, tablelen)
    encoded.gsub!(/B/, tablelen+5)
    encoded += table
    encoded += nonascii
  end

end end end
