require 'socket'

class SocksConn
  attr_accessor :client
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
  def process
    ver, nmeth = client.read(2).unpack("C2")
    methods = client.read(nmeth).unpack("C%d" % nmeth)

    unless methods.include? 0x00 and ver == 0x05
      debug("%s doesn't support ANON, rejecting" % client_str)
      client.write([0x05,0xff].pack("C*"))
      return
    end

    client.write([0x05,0x00].pack("C*"))

    ver, cmd, rsv, atyp = client.read(4).unpack("C*")
    address = case atyp
      when 0x01 #ipv4
        client.read(4).unpack("C*") # unpack in octets
      when 0x03 #domainname
        length, = client.read(1).unpack("C")
        client.read(length)
      when 0x04 #ipv6
        client.read(16)
    end

    port, = client.read(2).unpack("n")
    if atyp == 0x04
      debug("%s: ipv6 not supported" % client_str)
      client.write([0x05080001, 0x00, 0x00].pack("NNn"))
      return
    end

    case cmd
      when 0x01
        connect address, port, atyp
      when 0x02
        bind address, port, atyp
      when 0x03
        associate address, port, atyp
    end
  end

  # commands
  # 0x01 connect
  # 0x02 bind
  # 0x03 udp associate
  # replies
  # 0x00 success
  # 0x01 general socks server fail
  # 0x02 connection not allowed
  # 0x03 network unreachable
  # 0x04 host unreachable
  # 0x05 connection refused
  # 0x06 ttl expired
  # 0x07 command not supported
  # 0x08 address type not supported
  # ... unassigned
  def reply rep, atyp, addr=0, port=0
    client.write([0x05,rep,0x00,0x01].pack("C*"))
    case atyp
      when 0x01
        a = addr.pack("CCCC")
        client.write(a)
      when 0x03
        client.write([addr.length,addr].pack("Ca*"))
    end
    client.write([port].pack("n"))
    msg = case rep
      when 0x00
        "Successful"
      when 0x01
        "General failure"
      when 0x02
        "Connection not allowed"
      when 0x03
        "Network unreachable"
      when 0x04
        "Host unreachable"
      when 0x05
        "Connection refused"
      when 0x06
        "TTL Expired"
      when 0x07
        "Command not supported"
      when 0x08
        "Address type not supported"
    end
    debug("%s: %s" % [msg, ("%s.%s.%s.%s:%s" % (addr + [port.inspect]))])
  end
  def connect addr, port, atyp
    # connect a server port to a remote host port
    begin
      con = case atyp
        when 0x01 #ipv4
          a = "%d.%d.%d.%d" % addr
          TCPSocket.new(a, port)
        when 0x03 #domain
          TCPSocket.new(addr, port)
      end
    rescue Exception => e
      puts e.class
      case e
        when Errno::ENETUNREACH
          reply 0x03, 0x01, [0x00]*4, 0x00
        when Errno::EHOSTUNREACH
          reply 0x04, 0x01, [0x00]*4, 0x00
        when Errno::ECONNREFUSED
          reply 0x05, 0x01, [0x00]*4, 0x00
        else
          debug e.backtrace
          reply 0x01, 0x01, [0x00]*4, 0x00
      end
      return
    end
    addr = con.addr
    bport = addr[1]
    baddr = addr[3].split(".").map {|x| x.to_i}
    reply 0x00, 0x01, baddr, bport

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
    threads.each {|t| t.join }
    debug "Connection done"
  end
  def bind addr, port, atype
    debug("command not implemented BIND")
    reply 0x07, atype, addr, port
  end
  def associate assoc_addr, assoc_port, atype
    addr_proto, addr_str = case atype
      when 0x01
        ar, str = [assoc_addr.pack("CCCC"), "%d.%d.%d.%d" % assoc_addr]
        if str == "0.0.0.0"
          str = client.peeraddr[3]
          ar = str.split(".").map {|x| x.to_i}
        end
        [ar, str]
      when 0x03
        [[assoc_addr.length, assoc_addr].pack("Ca*"), assoc_addr]
    end
    port_proto = [assoc_port].pack("n")

    debug "Associating %s:%s for %s" % [addr_str, assoc_port, client_str]

    assoc = UDPSocket.new
    assoc.bind(client.addr[3], 0)

    bcon = UDPSocket.new
    bcon.bind("0.0.0.0", 0)

    # construct reply
    raddr = client.addr[3].split(".").map {|x| x.to_i}
    reply 0x00, 0x01, raddr, assoc.addr[1]

    debug("Associated: %s:%s <=> %s:%s" % [addr_str,assoc_port,assoc.addr[3],assoc.addr[1]])
    # relay datagrams
    debug assoc.addr.inspect
    loop do
      if list = IO.select([assoc,bcon,client], nil, nil, 1)
        debug "Select #{list.inspect}"
        list[0].each do |s|
          msg, snd_addr = s.recvfrom(1500) unless s == client
          debug "Recvfrom #{snd_addr.inspect}"
          case s
            when assoc
              # parse header
              rsv, frag, atyp, rest = msg.unpack("nCCa*")
              next unless frag == 0
              addr = case atyp
                when 0x01
                  addr, rest = rest.unpack("a4a*")
                  addr = addr.unpack("C4")
                  addr = "%d.%d.%d.%d" % addr
                when 0x03
                  len, rest = rest.unpack("Ca*")
                  addr, rest = rest.unpack("a%da*" % len)
              end
              port, rest = rest.unpack("na*")
              bcon.send rest, 0, addr, port
            when bcon
              # create header
              rsv, frag, atyp, addr, port = 0, 0, 1, snd_addr[3], snd_addr[1]
              addr = addr.split(".").map {|x| x.to_i}
              debug "Send to #{addr_str.inspect}, #{assoc_port.inspect}"
              assoc.send addr_str, assoc_port,
                ([rsv,frag,atyp] + addr + [port,msg]).pack("nCCC4na*")
            when client
              data = client.recv 1024
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
      SocksConn.new(client).process
    rescue Exception => e
      puts e
      puts e.class
      puts e.backtrace
    end
    client.close unless client.closed?
  end
end
