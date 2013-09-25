#
# Http Proxy - jduck
#

require 'rex/proto/http/server'

module Rex
module Proto
module Proxy


#
# The Proxy::Http class
#
class Http < Rex::Proto::Http::Server

protected

  # 
  # Put humpty dumpty back together again.
  #
  def rebuild_uri(request)
    # reconstitute the requested URI based on the parts
    uri = "#{request.resource}?"

    # NOTE: #normalize! screws with the request, so fix its madness.
    if uri =~ /:\/[^\/]/
      uri.gsub!(':/', '://')
    end

    # reconstitute the query string
    vars = []
    request.qstring.each { |k,v|
      vars << "#{k}=#{v}"
    }

    # combine resource and qstring
    uri << vars.join('&')
    uri
  end

  def send_ok(cli, request)
    ok = Rex::Proto::Http::Response::OK.new
    cli.put(ok.to_s)
  end


  # Overrides for stuff from Rex::Proto::Http::Server

  def dispatch_request(cli, request)
    #print_status("request: #{request.inspect}")
    case request.method

    when "GET", "POST"
      uri = URI.parse(rebuild_uri(request))
      #print_status("#{request.method} - #{uri.scheme} :// #{uri.host} : #{uri.port} #{uri.path}")

      # Now, we must connect to the target server and repeat the request.
      rcli = Rex::Proto::Http::Client.new(
        uri.host,
        uri.port || 80,
        self.context)
      # We dont want to send the original host header, though it should be the same
      request.headers.delete('Host')

      # Send the request
      rreq = rcli.request_raw({
        'uri' => uri.path,
        'method' => request.method,
        'headers' => request.headers,
        'data' => request.body,
        })

      begin
        # Read the response
        resp = rcli.send_recv(rreq)

        # Send it back to the requesting client
        cli.put(resp.to_s)

      rescue
        send_e404(cli, request)

      end

      # Bye!
      close_client(rcli)
      close_client(cli)

    when "CONNECT"
      host,port = request.resource.split(':')
      port = port.to_i
      
      # only tunnel SSL requests
      if port != 443
        send_e404(cli, request)
        close_client(cli)
        return
      end

      #print_status("#{request.method}: #{host} : #{port} (#{request.body.length} byte body)")

      # Now, we must connect to the target server and relay the data...
      # NOTE: according to rfc2817, the data accompanying this request should be included too.
      begin
        rcli = Rex::Socket::Tcp.create({
          'PeerHost' => host,
          'PeerPort' => port,
          'Context'  => self.context,
          })

      rescue ::Exception => e
        #print_error("Could not connect to requested host (#{host}): #{e.message}")
        send_e404(cli, request)
        close_client(cli)
        return

      end

      # don't let the server's client monitor see this guy anymore
      remove_client(cli)

      # Tell the client it's go time.
      send_ok(cli, request)

      # Relay the data back and forth
      cli.extend(Rex::Proto::Proxy::Relay)
      rcli.extend(Rex::Proto::Proxy::Relay)
      cli.relay(self, "HttpProxySSLRelay (c2s)", rcli)
      rcli.relay(self, "HttpProxySSLRelay (s2c)", cli)

      # If we are given a trusted CA cert to sign with, we could also 
      # transparently generate a CERT and MITM the SSL data.

      raise ::EOFError
    end

  end

end

end
end
end

