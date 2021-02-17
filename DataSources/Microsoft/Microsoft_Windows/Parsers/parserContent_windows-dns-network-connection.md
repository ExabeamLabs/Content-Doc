#### Parser Content
```Java
{
Name = windows-dns-network-connection
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "network-connection-successful"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """AddressFamily=""", """PacketType=""", """RemoteHostName=""", """UserSid=""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """TransportHeaderSizeBytes=({bytes}\d+)""",
    """PacketType=({activity}.+?)\s*PacketTypeId=""",
    """RemoteAddress=({dest_ip}[^\s]+)\s+""",
    """RemotePort=({dest_port}.+?)\s*ProcessName=""",
    """Direction=({direction}.+?)\s*Protocol=""",
    """RemoteHostName=({host}[^\s]+)\s+""",
    """ProcessName="*(unknown|(({process_name}({directory}([^\\]+\\)+)?({process}.+?))))"*\s*UserName=""",
    """Protocol=({protocol}.+?)\s*ProtocolId=""",
    """LocalAddress=({src_ip}[^\s]+)\s+""",
    """LocalPort=({src_port}.+?)\s*RemoteHostName=""",
    """UserSid=(unknown|({user_sid}.+?))\s*UserId=""",
    """UserName="*(unknown|((nt authority|({domain}[^\\\/]+))[\\\/])?([Ss]ystem|localsystem|network service|({user}.+?)))"*\s*UserSid=""",
    """UserId=({user_id}.+?)\s*HeaderSizeBytes=""",
  ]
}
```