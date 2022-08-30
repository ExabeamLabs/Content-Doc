#### Parser Content
```Java
{
Name = s-infoblox-one-dhcp-vpn-connection
  DataType = "vpn-connection"
  Vendor = Infoblox
  Product = BloxOne
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """openvpn-master[""", """Peer Connection Initiated with [AF_INET]""" ]
  Fields = [ 
     """\d\d:\d\d:\d\d\s{1,100}({host}[\w.-]{1,2000})\s{1,100}({src_ip}[a-fA-F\d.:]{1,2000}?)\s{1,100}({additional_info}[^~]{1,2000}?)\s{0,100}$""",
     """({event_name}Peer Connection Initiated) with [^\]]{1,2000}\]({dest_ip}[a-fA-F\d.:]{1,2000}?):({dest_port}\d{1,100})"""
	  
  ]


}
```