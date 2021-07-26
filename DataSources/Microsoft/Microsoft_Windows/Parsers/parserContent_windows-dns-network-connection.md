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
    """TransportHeaderSizeBytes=({bytes}\d{1,100})""",
    """PacketType=({activity}.+?)\s{0,100}PacketTypeId=""",
    """RemoteAddress=({dest_ip}[^\s]{1,2000})\s{1,100}""",
    """RemotePort=({dest_port}.+?)\s{0,100}ProcessName=""",
    """Direction=({direction}.+?)\s{0,100}Protocol=""",
    """RemoteHostName=({host}[^\s]{1,2000})\s{1,100}""",
    """ProcessName="{0,20}(unknown|(({process_name}({directory}([^\\]{1,2000}\\)+)?({process}.+?))))"{0,20}\s{0,100}UserName=""",
    """Protocol=({protocol}.+?)\s{0,100}ProtocolId=""",
    """LocalAddress=({src_ip}[^\s]{1,2000})\s{1,100}""",
    """LocalPort=({src_port}.+?)\s{0,100}RemoteHostName=""",
    """UserSid=(unknown|({user_sid}.+?))\s{0,100}UserId=""",
    """UserName="{0,20}(unknown|((nt authority|({domain}[^\\\/]{1,2000}))[\\\/])?([Ss]ystem|localsystem|network service|({user}.+?)))"{0,20}\s{0,100}UserSid=""",
    """UserId=({user_id}.+?)\s{0,100}HeaderSizeBytes=""",
  ]
}
```