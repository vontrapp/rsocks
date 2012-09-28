require 'socket'
require 'stringio'

class Socks5
  attr_accessor :client
  # constants
  VERSION = 5
  RSV = 0

  ADDR_IP4 = 1
  ADDR_DOMAIN = 3
  ADDR_IP6 = 4
  ADDR_UNKNOWN = 0x10

  CMD_CONNECT = 1
  CMD_BIND = 2
  CMD_ASSOCIATE = 3
  CMD_UDPBIND = 0x10

  RSP_SUCCESS = 0
  RSP_FAIL = 1
  RSP_REJECT = 2 # not allowed under ruleset
  RSP_NETUNREACH = 3
  RSP_HOSTUNREACH = 4
  RSP_CONNREFUSED = 5
  RSP_TTL = 6
  RSP_NOCOMMAND = 7
  RSP_NOADDRTYPE = 8

  module SocksUtil
    def addr_pack addr, atyp=0, port=nil
      # returns [atyp, socks encoded addr]
      apack = case atyp
        when ADDR_IP4
          if Array === addr
            [atyp, addr].pack("CCCCC")
          else
            [atyp, addr].pack("CN")
          end
        when ADDR_DOMAIN
          [atyp, addr.length, addr].pack("CCa*")
        when ADDR_IP6
          # assume it's just a byte array (string)
          addr
        else
          # return "0.0.0.0" as IPV4
          [1,0].pack("CN")
      end
      apack << [port].pack("n") if port
      apack
    end
    def addr_unpack stream
      # unpacks the atyp and addr from the stream
      if String === stream
        stream = StringIO.new stream
      end
      atyp, = stream.read(1).unpack("C")
      addr = case atyp
        when ADDR_IP4
          stream.read(4).unpack("N").first # unpack in octets
        when ADDR_DOMAIN
          length, = stream.read(1).unpack("C")
          stream.read(length)
        when ADDR_IP6
          stream.read(16)
      end
      [atyp, addr]
    end
    def addr_str addr, atyp=0
      # turns addr into a human string
      if atyp == 0
        atyp = addr_type addr
      end
      case atyp
        when ADDR_IP4
          [addr].pack("N").unpack("C*").map {|x| x.to_s}.join(".")
        when ADDR_DOMAIN
          addr
        when ADDR_IP6
          addr.unpack("n*").map {|x| "%04x" % x}.join(":")
        else
          addr.inspect
      end
    end
    def addr_strtoip4 addr
      addr = addr.split(".")
      if addr.length != 4
        0
      else
        addr.map {|x| x.to_i}.pack("C*").unpack("N").first
      end
    end
    def addr_type addr
      # deduce the atyp of addr
      case addr
        when Fixnum
          ADDR_IP4
        when String
          ADDR_DOMAIN
        else
          ADDR_UNKNOWN
      end
    end
  end

  extend SocksUtil
  include SocksUtil

  def initialize c
    self.client = c
  end

  def debug str
    puts str
    STDOUT.flush
  end
  def client_str
    client.peeraddr[2]
  end

  def authenticate
    ver, nmeth = client.read(2).unpack("C2")
    methods = client.read(nmeth).unpack("C%d" % nmeth)

    unless methods.include? 0x00 and ver == VERSION
      debug("%s doesn't support ANON, rejecting" % client_str)
      client.write([VERSION, 0xFF].pack("C*"))
      return false
    end

    client.write([VERSION,0x00].pack("C*"))
    return true
  end

  def request
    # return cmd, atyp, addr, port
    # return response number if invalid or not supported
    ver, cmd, rsv = client.read(3).unpack("C*")
    atyp, addr = addr_unpack client

    port, = client.read(2).unpack("n")

    req = cmd, atyp, addr, port
    return RSP_FAIL, *req unless rsv == 0 and ver == 5
    return RSP_NOADDR, *req if atyp == ADDR_IP6 or atyp == ADDR_UNKNOWN
    return filter_request *req
  end
  def filter_request cmd, atyp, addr, port
    # return "not allowed" based on filtering/authentication
    # otherwise, return 0x00
    [RSP_SUCCESS, cmd, atyp, addr, port]
  end

  def process
    authenticate or return
    rsp, *req = request
    cmd, atyp, addr, port = req
    unless rsp == RSP_SUCCESS
      return reply rsp, *req
    end
    # we hav RSP_SUCCESS for now, but could still have connection errors

    begin
      case cmd
        when CMD_CONNECT
          connect *req[1,3]
        when CMD_BIND
          bind *req[1,3]
        when CMD_ASSOCIATE
          associate *req[1,3]
        when CMD_UDPBIND
          udpbind *req[1,3]
      end
    rescue Exception => e
      debug e
      debug e.class
      debug e.backtrace
      unless client.closed? or client.eof
        reply RSP_FAIL, *req
      end
    end
    unless client.eof or client.closed?
      client.read
    end
    unless client.closed?
      client.recv(4096)
      client.close
    end
  end

  def reply rsp, cmd, atyp, addr=0, port=0
    client.write([VERSION,rsp,RSV].pack("C*"))
    client.write(addr_pack addr, atyp, port)

    debugmsg = case rsp
      when RSP_SUCCESS
        "Successful"
      when RSP_FAIL
        "General failure"
      when RSP_REJECT
        "Connection not allowed"
      when RSP_NETUNREACH
        "Network unreachable"
      when RSP_HOSTUNREACH
        "Host unreachable"
      when RSP_CONNREFUSED
        "Connection refused"
      when RSP_TTL
        "TTL Expired"
      when RSP_NOCOMMAND
        "Command not supported"
      when RSP_NOADDRTYPE
        "Address type not supported"
    end
    debug("%s: %s:%s" % [debugmsg, addr_str(addr, atyp), port])
  end
  def connect atyp, addr, port
    # connect a server port to a remote host port
    begin
      con = TCPSocket.new(addr_str(addr, atyp), port)
    rescue Exception => e
      puts e.class
      req = CMD_CONNECT, atyp, addr, port
      case e
        when Errno::ENETUNREACH
          reply RSP_NETUNREACH, *req
        when Errno::EHOSTUNREACH
          reply RSP_HOSTUNREACH, *req
        when Errno::ECONNREFUSED
          reply RSP_CONNREFUSED, *req
        else
          debug e.backtrace
          reply RSP_FAIL, *req
      end
      return
    end
    addr = con.addr
    bport = addr[1]
    baddr = addr[3]
    reply RSP_SUCCESS, CMD_CONNECT, 0x01, addr_strtoip4(baddr), bport

    threads = [[con,client],[client,con]].map do |src,dst|
      Thread.new do
        begin
          IO.copy_stream(src,dst)
          src.close_read
          dst.close_write
        rescue
        end
      end
    end
    threads.each {|t| t.join}
    debug "Connection done"
  end
  def bind atyp, addr, port
    debug("BIND not implemented")
    reply 0x07, CMD_BIND, atyp, addr, port
  end
  def associate atyp, assoc_addr, assoc_port
    addr_proto = addr_pack assoc_addr, atyp, assoc_port
    addr_str = addr_str assoc_addr, atyp

    port_proto = [assoc_port].pack("n")

    debug "Associating %s:%s for %s" % [addr_str, assoc_port, client_str]

    assoc_dstaddr = case atyp
      when ADDR_IP4
        assoc_addr == 0 ? nil : addr_str(asoc_addr, atyp)
      when ADDR_DOMAIN
        assoc_addr == "0.0.0.0" ? nil : assoc_addr
    end
    assoc_dstport = assoc_port == 0 ? nil : assoc_port

    raddr = addr_strtoip4 client.addr[3]
    ratyp = ADDR_IP4
    # be SSH aware
    if raddr == 0x7f000001 # localhost
      raddr, ratyp = Socket.gethostname, ADDR_DOMAIN
    end
    assoc = UDPSocket.new
    assoc.bind(addr_str(raddr), 0)

    bcon = UDPSocket.new
    bcon.bind("0.0.0.0", 0)

    # construct reply
    debug "Reply ASSOCIATE #{ratyp} #{addr_str raddr, ratyp}"
    reply RSP_SUCCESS, CMD_ASSOCIATE, ratyp, raddr, assoc.addr[1]

    debug("Associated: %s:%s <=> %s:%s <=> %s:%s" %
      [addr_str,assoc_port,assoc.addr[3],assoc.addr[1],
        bcon.addr[3], bcon.addr[1]])
    # relay datagrams
    loop do
      if list = IO.select([assoc,bcon,client], nil, nil, 1)
        debug "selected #{list[0].inspect}"
        list[0].each do |s|
          msg, snd_addr = s.recvfrom(1500) unless s == client
          debug "Recvfrom #{snd_addr.inspect}" if snd_addr
          case s
            when assoc
              # parse header
              assoc_dstaddr ||= snd_addr[3]
              assoc_dstport ||= snd_addr[1]
              sio = StringIO.new msg
              rsv, frag = sio.read(3).unpack("nC")
              atyp, addr = addr_unpack sio
              addr = addr_str addr, atyp
              port = sio.read(2).unpack("n").first
              debug "Sending from cleint to #{addr}:#{port}"
              bcon.send sio.read, 0, addr, port
            when bcon
              # create header
              rsv, frag, atyp, addr, port = 0, 0, ADDR_IP4,
                snd_addr[3], snd_addr[1]
              addr = addr_strtoip4 addr
              if assoc_dstaddr and assoc_dstport
                debug "Send to #{assoc_dstaddr}:#{assoc_dstport}"
                snd = [rsv,frag].pack("nC")
                snd << addr_pack(addr, atyp, port)
                snd << msg
                assoc.send snd, 0, addr_str, assoc_port
              else
                debug "Not sending because association not complete"
              end
            when client
              data = client.recv 1024
              debug data.unpack("C*").map {|x| x.to_s(16)}.join
              if client.eof
                debug "got EOF on client stream, terminating association"
                return
              end
          end
        end
      end
    end
  end
end

server = TCPServer.open(1083)
server.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, true)

Thread.abort_on_exception = true

loop do
  Thread.start(server.accept) do |client|
    begin
      STDERR.puts "%s connected" % client.peeraddr[2]
      Socks5.new(client).process
    rescue Exception => e
      puts e
      puts e.class
      puts e.backtrace
      client.close unless client.closed?
    end
  end
end
