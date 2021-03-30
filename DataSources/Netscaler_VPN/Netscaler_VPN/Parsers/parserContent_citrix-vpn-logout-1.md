#### Parser Content
```Java
{
Name = citrix-vpn-logout-1
  Vendor = Netscaler VPN
  Lms = Direct
  DataType = "logout"
  TimeFormat = "MM/dd/yyyy:HH:mm:ss z"
  Conditions = [ """ SSLVPN ICAEND_CONNSTAT """ ]
  Fields = [
    """({time}\d\d/\d\d/\d\d\d\d:\d\d:\d\d:\d\d \w+)\s+({host}[\w.\-]+)(\s+\S+){3}\s+SSLVPN ({event_name}ICAEND_CONNSTAT)\s""",
    """\sSource\s+({src_ip}[a-fA-F\d.:]+?)(:({src_port}\d+))?\s""",
    """\sDestination\s+({dest_ip}[a-fA-F\d.:]+?)(:({dest_port}\d+))?\s""",
    """\susername:domainname\s+({user}[^\s:]+):({domain}[^\s]+)""",
    """\sDuration ({duration}\S+)""",
    """\sTotal_bytes_send\s+({bytes_out}\d+)""",
    """\sTotal_bytes_recv\s+({bytes_in}\d+)""",
    """\sconnectionId\s+({sconnection_id}\S+)""",
  ]
}
```