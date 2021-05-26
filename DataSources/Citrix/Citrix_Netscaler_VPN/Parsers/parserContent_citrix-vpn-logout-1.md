#### Parser Content
```Java
{
Name = citrix-vpn-logout-1
  Vendor = Citrix
  Product = Citrix Netscaler VPN
  Lms = Direct
  DataType = "logout"
  TimeFormat = "MM/dd/yyyy:HH:mm:ss z"
  Conditions = [ """ SSLVPN ICAEND_CONNSTAT """ ]
  Fields = [
    """({time}\d\d/\d\d/\d\d\d\d:\d\d:\d\d:\d\d \w+)\s{1,100}({host}[\w.\-]{1,2000})(\s{1,100}\S+){3}\s{1,100}SSLVPN ({event_name}ICAEND_CONNSTAT)\s""",
    """\sSource\s{1,100}({src_ip}[a-fA-F\d.:]{1,2000}?)(:({src_port}\d{1,100}))?\s""",
    """\sDestination\s{1,100}({dest_ip}[a-fA-F\d.:]{1,2000}?)(:({dest_port}\d{1,100}))?\s""",
    """\susername:domainname\s{1,100}({user}[^\s:]{1,2000}):({domain}[^\s]{1,2000})""",
    """\sDuration ({duration}\S+)""",
    """\sTotal_bytes_send\s{1,100}({bytes_out}\d{1,100})""",
    """\sTotal_bytes_recv\s{1,100}({bytes_in}\d{1,100})""",
    """\sconnectionId\s{1,100}({sconnection_id}\S+)""",
  ]
}
```