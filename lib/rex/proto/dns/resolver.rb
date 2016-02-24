require 'net/dns/resolver'

module Rex
module Proto
module DNS

  ##
  # Provides Rex::Sockets compatible version of Net::DNS::Resolver
  ##
  class Resolver < Net::DNS::Resolver

    Defaults = {
      :config_file => "/dev/null", # default can lead to info leaks
      :log_file => "/dev/null", # formerly $stdout, should be tied in with our loggers
      :port => 53,
      :searchlist => [],
      :nameservers => [IPAddr.new("127.0.0.1")],
      :domain => "",
      :source_port => 0,
      :source_address => IPAddr.new("0.0.0.0"),
      :retry_interval => 5,
      :retry_number => 4,
      :recursive => true,
      :defname => true,
      :dns_search => true,
      :use_tcp => false,
      :ignore_truncated => false,
      :packet_size => 512,
      :tcp_timeout => TcpTimeout.new(30),
      :udp_timeout => UdpTimeout.new(30)
    }

    #
    # Provide override for initializer to use local Defaults constant
    #
    # @param config [Hash] Configuration options as conusumed by parent class
    def initialize(config = {})
      raise ResolverArgumentError, "Argument has to be Hash" unless config.kind_of? Hash
      # config.key_downcase!
      @config = Defaults.merge config
      @raw = false

      # New logger facility
      @logger = Logger.new(@config[:log_file])
      @logger.level = $DEBUG ? Logger::DEBUG : Logger::WARN

      #------------------------------------------------------------
      # Resolver configuration will be set in order from:
      # 1) initialize arguments
      # 2) ENV variables
      # 3) config file
      # 4) defaults (and /etc/resolv.conf for config)
      #------------------------------------------------------------



      #------------------------------------------------------------
      # Parsing config file
      #------------------------------------------------------------
      parse_config_file

      #------------------------------------------------------------
      # Parsing ENV variables
      #------------------------------------------------------------
      parse_environment_variables

      #------------------------------------------------------------
      # Parsing arguments
      #------------------------------------------------------------
      config.each do |key,val|
        next if key == :log_file or key == :config_file
        begin
          eval "self.#{key.to_s} = val"
        rescue NoMethodError
          raise ResolverArgumentError, "Option #{key} not valid"
        end
      end
    end
    #
    # Provides current proxy setting if configured
    #
    # @return [String] Current proxy configuration
    def proxies
      @config[:proxies].inspect if @config[:proxies]
    end

    #
    # Configure proxy setting and additional timeout
    #
    # @param prox [String] SOCKS proxy connection string
    # @param timeout_added [Fixnum] Added TCP timeout to account for proxy
    def proxies=(prox, timeout_added = 250)
      return if prox.nil?
      if prox.is_a?(String) and prox.strip =~ /^socks/i
        @config[:proxies] = prox.strip
        @config[:use_tcp] = true
        self.tcp_timeout = self.tcp_timeout.to_s.to_i + timeout_added
        @logger.info "SOCKS proxy set, using TCP, increasing timeout"
      else
        raise ResolverError, "Only socks proxies supported"
      end
    end

    #
    # Send DNS request over appropriate transport and process response
    #
    # @param argument
    # @param type [Fixnum] Type of record to look up
    # @param cls [Fixnum] Class of question to look up
    def send(argument,type=Net::DNS::A,cls=Net::DNS::IN)
      if @config[:nameservers].size == 0
        raise ResolverError, "No nameservers specified!"
      end

      method = self.use_tcp? ? :send_tcp : :send_udp

      if argument.kind_of? Net::DNS::Packet
        packet = argument
      elsif argument.kind_of? Resolv::DNS::Message
        packet = Net::DNS::Packet.parse(argument.encode)
      else
        packet = make_query_packet(argument,type,cls)
      end

      # Store packet_data for performance improvements,
      # so methods don't keep on calling Packet#data
      packet_data = packet.data
      packet_size = packet_data.size

      # Choose whether use TCP, UDP
      if packet_size > @config[:packet_size] # Must use TCP
        @logger.info "Sending #{packet_size} bytes using TCP due to size"
        method = :send_tcp
      else # Packet size is inside the boundaries
        if use_tcp? or !(proxies.nil? or proxies.empty?) # User requested TCP
          @logger.info "Sending #{packet_size} bytes using TCP due to tcp flag"
          method = :send_tcp
        else # Finally use UDP
          @logger.info "Sending #{packet_size} bytes using UDP"
          method = :send_udp unless method == :send_tcp 
        end
      end

      if type == Net::DNS::AXFR
        @logger.warn "AXFR query, switching to TCP" unless method == :send_tcp
        method = :send_tcp
      end

      ans = self.__send__(method,packet_data)

      unless (ans and ans[0].length > 0)
        @logger.fatal "No response from nameservers list: aborting"
        raise NoResponseError
        return nil
      end

      @logger.info "Received #{ans[0].size} bytes from #{ans[1][2]+":"+ans[1][1].to_s}"
      response = Net::DNS::Packet.parse(ans[0],ans[1])

      if response.header.truncated? and not ignore_truncated?
        @logger.warn "Packet truncated, retrying using TCP"
        self.use_tcp = true
        begin
          return send(argument,type,cls)
        ensure
          self.use_tcp = false
        end
      end

      return response
    end

    #
    # Send request over TCP
    #
    # @param packet_data [String] Data segment of DNS request packet
    # @param prox [String] Proxy configuration for TCP socket
    #
    # @return ans [String] Raw DNS reply
    def send_tcp(packet_data,prox = @config[:proxies])
      ans = nil
      length = [packet_data.size].pack("n")
      @config[:nameservers].each do |ns|
        begin
          socket = nil
          @config[:tcp_timeout].timeout do
            catch(:next_ns) do
              begin
                socket = Rex::Socket::Tcp.create(
                  'PeerHost' => ns.to_s,
                  'PeerPort' => @config[:port].to_i,
                  'Proxies' => prox
                )
              rescue
                @logger.warn "TCP Socket could not be established to #{ns}:#{@config[:port]} #{@config[:proxies]}"
                throw :next_ns
              end
              next unless socket #
              @logger.info "Contacting nameserver #{ns} port #{@config[:port]}"
              socket.write(length+packet_data)
              got_something = false
              loop do
                buffer = ""
                ans = socket.recv(Net::DNS::INT16SZ)
                if ans.size == 0
                  if got_something
                    break #Proper exit from loop
                  else
                    @logger.warn "Connection reset to nameserver #{ns}, trying next."
                    throw :next_ns
                  end
                end
                got_something = true
                len = ans.unpack("n")[0]

                @logger.info "Receiving #{len} bytes..."

                if len.nil? or len == 0
                  @logger.warn "Receiving 0 length packet from nameserver #{ns}, trying next."
                  throw :next_ns
                end

                while (buffer.size < len)
                  left = len - buffer.size
                  temp,from = socket.recvfrom(left)
                  buffer += temp
                end

                unless buffer.size == len
                  @logger.warn "Malformed packet from nameserver #{ns}, trying next."
                  throw :next_ns
                end
                if block_given?
                  yield [buffer,["",@config[:port],ns.to_s,ns.to_s]]
                else
                  return [buffer,["",@config[:port],ns.to_s,ns.to_s]]
                end
              end
            end
  			end
		  rescue Timeout::Error
			  @logger.warn "Nameserver #{ns} not responding within TCP timeout, trying next one"
			  next
		  ensure
			  socket.close if socket
		  end
		end
		return nil
	  end

    #
    # Send request over UDP
    #
    # @param packet_data [String] Data segment of DNS request packet
    #
    # @return ans [String] Raw DNS reply
    def send_udp(packet_data)
      ans = nil
      response = ""
      @config[:nameservers].each do |ns|
        begin
          @config[:udp_timeout].timeout do
            begin
              socket = Rex::Socket::Udp.create(
                'PeerHost' => ns.to_s,
                'PeerPort' => @config[:port].to_i
              )
            rescue
              @logger.warn "UDP Socket could not be established to #{ns}:#{@config[:port]}"
              return nil
            end
            @logger.info "Contacting nameserver #{ns} port #{@config[:port]}"
            #socket.sendto(packet_data, ns.to_s, @config[:port].to_i, 0)
            socket.write(packet_data)
            ans = socket.recvfrom(@config[:packet_size])
          end
          break if ans
        rescue Timeout::Error
          @logger.warn "Nameserver #{ns} not responding within UDP timeout, trying next one"
          next
        end
      end
      return ans
    end
  end

end
end
end