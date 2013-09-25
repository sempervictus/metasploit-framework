##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'thread'
require 'msf/core'
require 'rex/proto/proxy/http'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'HTTP Proxy Server',
      'Description' => 'This module provides an HTTP proxy server that uses the builtin Metasploit routing to relay connections.',
      'Author'      => [ 'jduck' ],
      'License'     => MSF_LICENSE,
      'Actions'     =>
        [
          [ 'Proxy' ]
        ],
      'PassiveActions' =>
        [
          'Proxy'
        ],
      'DefaultAction'  => 'Proxy'))

    register_options(
      [
        OptString.new( 'SRVHOST', [ true,  "The address to listen on", '0.0.0.0' ] ),
        OptPort.new('SRVPORT', [ true, "The daemon port to listen on", 80 ]),
      ], self.class)
  end

  def setup
    super
    @mutex = ::Mutex.new
    @hproxy = nil
  end

  def cleanup
    @mutex.synchronize do
      if( @hproxy )
        print_status( "Stopping the HTTP proxy server" )
        @hproxy.stop
        @hproxy = nil
      end
    end
    super
  end

  def run
    opts = {
      'ServerHost' => datastore['SRVHOST'],
      'ServerPort' => datastore['SRVPORT'],
      'Context' => {'Msf' => framework, 'MsfExploit' => self}
    }

    @hproxy = Rex::Proto::Proxy::Http.new(
      datastore['SRVPORT'],
      datastore['SRVHOST'],
      false,
      {
        'Msf' => framework,
        'MsfExploit' => self
      })

    print_status( "Starting the HTTP proxy server" )

    @hproxy.start
    @hproxy.wait
  end

end

