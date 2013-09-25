require 'thread'

module Rex
module Proto
module Proxy

require 'rex/proto/proxy/socks4a'
require 'rex/proto/proxy/http'

#
# A mixin for a socket to perform a relay to another socket.
#
module Relay

  #
  # Relay data coming in from relay_sock to this socket.
  #
  def relay( relay_client, thread_name, relay_sock )
    @relay_client = relay_client
    @relay_sock   = relay_sock

    # start the relay thread (modified from Rex::IO::StreamAbstraction)
    @relay_thread = Rex::ThreadFactory.spawn(thread_name, false) do
      loop do
        closed = false
        buf    = nil

        begin
          s = Rex::ThreadSafe.select( [ @relay_sock ], nil, nil, 0.2 )
          if( s == nil || s[0] == nil )
            next
          end
        rescue
          closed = true
        end

        if( closed == false )
          begin
            buf = @relay_sock.sysread( 32768 )
            closed = true if( buf == nil )
          rescue
            closed = true
          end
        end

        if( closed == false )
          total_sent   = 0
          total_length = buf.length
          while( total_sent < total_length )
            begin
              data = buf[total_sent, buf.length]
              sent = self.write( data )
              if( sent > 0 )
                total_sent += sent
              end
            rescue
              closed = true
              break
            end
          end
        end

        if( closed )
          @relay_client.stop
          ::Thread.exit
        end
      end
    end

  end

end

end
end
end

