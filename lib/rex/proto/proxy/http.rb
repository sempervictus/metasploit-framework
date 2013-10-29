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


  def initialize(port = 80, listen_host = '0.0.0.0', ssl = false, context = {}, comm = nil, ssl_cert = nil,
    proxies = nil, rhost = nil, rport = nil, rssl = nil)
    super(port, listen_host, ssl, context, comm, ssl_cert)
    self.proxies = proxies # force requests through upstream proxy
    self.rhost = (rhost.nil? or rhost.empty?) ? nil : rhost # force all requests to remote host
    self.rport = rport.to_i == 0 ? nil : rport # ...
    self.rssl = rssl == true ? true : nil # force remote ssl
    self.strip_proxy_headers = false
    # List of headers to strip from final request - %w{Connection Proxy-Connection Content-Length Host}
    self.strip_headers = []
  end

  # #
  # # Custom setter for header removals
  # #
  # def strip_headers=(header_names=[])
  #   self.strip_headers = header_names.flatten.map { |hdr|
  #      hdr.kind_of?(String) ? hdr.split(/,|\s/).compact : hdr
  #   }.flatten.compact
  # end
  #
  # Callbacks that can be modified by consumers
  #
  def on_http_request(cli, req)
    if (on_http_request_proc)
      return on_http_request_proc.call(cli, req)
    end
    true
  end

  def on_http_response(cli, res)
    if (on_http_response_proc)
      return on_http_response_proc.call(cli, res)
    end
    true
  end

  def on_http_connect(cli, res)
    if (on_http_connect_proc)
      return on_http_connect_proc.call(cli, res)
    end
    true
  end

  attr_accessor :on_http_request_proc
  attr_accessor :on_http_response_proc
  attr_accessor :on_http_connect_proc
  attr_accessor :proxies, :rhost, :rport, :rssl
  attr_accessor :strip_headers, :strip_proxy_headers

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
    cli.put(Rex::Proto::Http::Response::OK.new.to_s)
  end

  # 
  # Removes proxy headers for "transparent" proxy
  #
  def strip_proxy_headers(request)
    request.headers.select {|h| h.downcase.strip.match(/^proxy/)}.map do |hdr|
      request.headers.delete(hdr)
    end
  end

  # Overrides for stuff from Rex::Proto::Http::Server

  def dispatch_request(cli, request)

    case request.method

    when "GET", "POST"
    #, "PUT", "TRACE", "DELETE", "UPDATE"
      begin
        uri = URI.parse(rebuild_uri(request))
      rescue ::Exception => e
        send_e404(cli, request)
        wlog("Exception in HttpProxy dispatch_request while parsing request URI: #{e.class}: #{e}")
        wlog("Call Stack\n#{e.backtrace.join("\n")}")
        close_client(cli)
        return

      end
      uri.path = '/' if uri.path.empty?
      $stdout.puts uri
      # Allow callers to change the incoming request
      request.extend(Request)
      request.uri_obj = uri

      return if not on_http_request(cli, request)

      # Set destonation port, check hardcoded, then uri, fall back to 80
      dport = self.rport.to_i > 0 ? self.rport : uri.port.to_i > 0 ? uri.port : 80  

      # Now, we must connect to the target server and repeat the request.
      # Force request to target host, and port if specified, or proxy
      rcli = Rex::Proto::Http::Client.new(
        self.rhost || uri.host,
        dport,
        self.context,
        self.rssl,
        nil,
        self.proxies)

      # Delete headers that end up getting duplicated. They should end up the
      # same value, but having two of them still isn't helpful :-/
      # request.headers.delete('Host')
      # request.headers.delete('Content-Length')

      # Remove bothersome headers from requests
      # self.strip_headers.map do |str_header|
      #   request.headers.delete(str_header) 
      # end

      # Send the request
      uri.query = '?' + uri.query if uri.query.length > 0
      rreq = rcli.request_raw({
        'uri' => uri.path + uri.query,
        'method' => request.method,
        'headers' => request.headers,
        'data' => request.body,
        })
$stdout.puts(rreq.to_s)
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
      return if not on_http_response(cli, resp)

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
      send_tcp_request(cli,request)
    end
  end

  def send_tcp_request(cli,request)
    host,port = request.resource.split(':')
    # Configure port and host settings if hard-coded
    port = self.rport.to_i > 0 ?  self.rport : port.to_i > 0 ? port : 80 
    host = self.rhost unless self.rhost.nil? or self.rhost.empty?

    return if not on_http_connect(cli, request)
    $stdout.puts("Connecting to #{host} #{port} with self #{self.rhost} #{self.rport}")
    # # only tunnel SSL requests
    # if port != 443
    #   send_e404(cli, request)
    #   ilog("HttpProxy: Rejecting CONNECT request for #{host}:#{port} from #{cli.peerhost} ...", LEV_2);
    #   close_client(cli)
    #   return
    # end

    # Now, we must connect to the target server and relay the data...
    # NOTE: according to rfc2817, the data accompanying this request should be included too.
    begin
      rcli = Rex::Socket::Tcp.create({
        'PeerHost' => host,
        'PeerPort' => port.to_i,
        'Context'  => self.context,
        'Proxies'  => self.proxies
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
    cli.relay(nil, "HttpProxySSLRelay (c2s)", rcli)#, self.on_http_request_proc)
    rcli.relay(nil, "HttpProxySSLRelay (s2c)", cli)#, self.on_http_response_proc)

    # If we are given a trusted CA cert to sign with, we could also 
    # transparently generate a CERT and MITM the SSL data.

  end

end

end
end
end

