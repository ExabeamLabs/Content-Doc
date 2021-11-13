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
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
    """\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d\s{1,100}({host}[\w\-.]{1,2000})""",
     """exabeam_host=(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^\s]{1,2000}))""",
     """({time}\d\d/\d\d/\d\d\d\d:\d\d:\d\d:\d\d)""",
     """User ({user_email}[^@\s]{1,2000}@[^@\s]{1,2000}) - Client_ip ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
     """User ({user}[^@\s]{1,2000}) - Client_ip ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
     """ Nat_ip ({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
     """SSLVPN_client_type\s{0,100}({vpn_client_type}[^\s]{1,2000}) - Group""",
     """Browser_type (\")+(?:-|({user_agent}[^"]{1,2000}))""",
     """Vserver\s{0,100}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
     ]
 DupFields = [ "vpn_client_type->app" ]


}
```