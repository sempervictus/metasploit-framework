#
# Http Proxy - jduck
#

require 'rex/proto/http/server'

module Rex
module Proto
module Proxy


module Request
  def initialize
    super
    self.uri_obj = nil
  end

  def uri_obj=
    self.uri = uri_obj
  end

  attr_accessor :uri_obj
end


module Response
  def initialize
    super
    self.orig_req = nil
  end

  def orig_req=
    self.req = orig_req
  end

  attr_accessor :orig_req
end


#
# The Proxy::Http class
#
class Http < Rex::Proto::Http::Server

  #
  # Callbacks that can be modified by consumers
  #
  def on_http_request(cli, req)
    if (on_http_request_proc)
      on_http_request_proc.call(cli, req)
    end
  end

  def on_http_response(cli, res)
    if (on_http_response_proc)
      on_http_response_proc.call(cli, res)
    end
  end

  attr_accessor :on_http_request_proc
  attr_accessor :on_http_response_proc

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

    vars_comb = vars.join('&')
    vars_comb.gsub!(/ /, '+')

    # combine resource and qstring
    uri << vars_comb
    uri
  end

  def send_ok(cli, request)
    ok = Rex::Proto::Http::Response::OK.new
    cli.put(ok.to_s)
  end


  # Overrides for stuff from Rex::Proto::Http::Server

  def dispatch_request(cli, request)
    case request.method

    when "GET", "POST"
      begin
        uri = URI.parse(rebuild_uri(request))
      rescue ::Exception => e
        send_e404(cli, request)
        wlog("Exception in HttpProxy dispatch_request while parsing request URI: #{e.class}: #{e}")
        wlog("Call Stack\n#{e.backtrace.join("\n")}")
        close_client(cli)
        return

      end

      # Allow callers to change the incoming request
      request.extend(Request)
      request.uri_obj = uri

      on_http_request(cli, request)

      # Now, we must connect to the target server and repeat the request.
      rcli = Rex::Proto::Http::Client.new(
        uri.host,
        uri.port || 80,
        self.context)

      # Delete headers that end up getting duplicated. They should end up the
      # same value, but having two of them still isn't helpful :-/
      request.headers.delete('Host')
      request.headers.delete('Content-Length')

      # Send the request
      rreq = rcli.request_raw({
        'uri' => uri.path + "?" + uri.query,
        'method' => request.method,
        'headers' => request.headers,
        'data' => request.body,
        })

      begin
        # Read the response
        resp = rcli.send_recv(rreq)

      rescue ::Exception => e
        send_e404(cli, request)
        wlog("Exception in HttpProxy dispatch_request while relaying request: #{e.class}: #{e}")
        wlog("Call Stack\n#{e.backtrace.join("\n")}")
        close_client(rcli)
        close_client(cli)
        return

      end

      # Add the original request (prior to rebuilding)
      resp.extend(Response)
      resp.orig_req = request

      # Don't rescue exceptions in this, they should be shown to whoever is
      # implementing on_http_response.
      on_http_response(cli, resp)

      begin
        # Send it back to the requesting client
        cli.put(resp.to_s)

      rescue ::Exception => e
        send_e404(cli, request)
        wlog("Exception in HttpProxy dispatch_request while relaying response: #{e.class}: #{e}")
        wlog("Call Stack\n#{e.backtrace.join("\n")}")

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
        ilog("HttpProxy: Rejecting CONNECT request for #{host}:#{port} from #{cli.peerhost} ...", LEV_2);
        close_client(cli)
        return
      end

      # Now, we must connect to the target server and relay the data...
      # NOTE: according to rfc2817, the data accompanying this request should be included too.
      begin
        rcli = Rex::Socket::Tcp.create({
          'PeerHost' => host,
          'PeerPort' => port,
          'Context'  => self.context,
          })

      rescue ::Exception => e
        wlog("Exception in Proxy dispatch_request while handling CONNECT: #{e.class}: #{e}")
        wlog("Call Stack\n#{e.backtrace.join("\n")}")

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
      cli.relay(nil, "HttpProxySSLRelay (c2s)", rcli)
      rcli.relay(nil, "HttpProxySSLRelay (s2c)", cli)

      # If we are given a trusted CA cert to sign with, we could also 
      # transparently generate a CERT and MITM the SSL data.

    end

  end

end

end
end
end

