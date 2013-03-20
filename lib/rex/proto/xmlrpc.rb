# -*- coding: binary -*-
# require 'rex/proto/xmlrpc/client'
# require 'rex/proto/xmlrpc/service'

require 'xmlrpc/client'
require 'rex/proto/http'

module XMLRPC

  class Client

    #USER_AGENT = "XMLRPC::Client (Ruby #{RUBY_VERSION})"

    include ParserWriterChooseMixin
    include ParseContentType


    # Constructors -------------------------------------------------------------------

    def initialize(host=nil, path=nil, port=nil, proxy_host=nil, proxy_port=nil,
                   user=nil, password=nil, use_ssl=nil, timeout=nil)

      @http_header_extra = nil
      @http_last_response = nil
      @cookie = nil

      @host       = host || "localhost"
      @path       = path || "/RPC2"
      @proxy_host = proxy_host
      @proxy_port = proxy_port
      @proxy_host ||= 'localhost' if @proxy_port != nil
      @proxy_port ||= 8080 if @proxy_host != nil
      @use_ssl    = use_ssl || false
      @timeout    = timeout || 30

      if use_ssl
        # require "net/https"
        @port = port || 443
      else
        @port = port || 80
      end

      @user, @password = user, password

      set_auth

      # convert ports to integers
      @port = @port.to_i if @port != nil
      @proxy_port = @proxy_port.to_i if @proxy_port != nil

      # HTTP object for synchronous calls
      Net::HTTP.version_1_2
      # @http = Net::HTTP.new(@host, @port, @proxy_host, @proxy_port)
      proxies = @proxy_host ? "http://#{@proxy_host}:#{@proxy_port}" : nil
      @http = Rex::Proto::Http::Client.new(@host, @port, nil, @use_ssl, nil, proxies, user, password)
      # @http.use_ssl = @use_ssl if @use_ssl
      # @http.read_timeout = @timeout
      # http.open_timeout = @timeout

      @parser = nil
      @create = nil
    end

  end
end
