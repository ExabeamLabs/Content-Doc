#### Parser Content
```Java
{
Name = raw-netscaler-vpn-start
  Vendor = Citrix
  Product = Citrix Netscaler
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "MM/dd/yyyy:HH:mm:ss"
  Conditions = [ "SSLVPN LOGIN", " Client_ip " ]
  Fields = [ 
    """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
    """\w+\s+\d+\s+\d\d:\d\d:\d\d\s+({host}[\w\-.]+)""",
     """exabeam_host=(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^\s]+))""",
     """({time}\d\d/\d\d/\d\d\d\d:\d\d:\d\d:\d\d)""",
     """User ({user_email}[^@\s]+@[^@\s]+) - Client_ip ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
     """User ({user}[^@\s]+) - Client_ip ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
     """ Nat_ip ({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
     """SSLVPN_client_type\s*({vpn_client_type}[^\s]+) - Group""",
     """Browser_type (\")+(?:-|({browser}[\w\-]+))""",
     """Browser_type (\")+(?:-|({browser}[\w\-]+)\/[\d\._]+)""",
     """Browser_type (\")+(?:-|({browser}[^\/]+).+({os}iOS|Android|BlackBerry|iPhone OS|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
     """Browser_type (\")+(?:-|Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
     """Browser_type (\")+(?:-|Mozilla\/.+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+Gecko\/\d+\s+({browser}\w+))""",
     """Vserver\s*({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
     ]
 DupFields = [ "vpn_client_type->app" ]
}
```