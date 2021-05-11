#### Parser Content
```Java
{
Name = raw-juniper-nwc-vpn-authsuccess-1
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  """ PulseSecure:""", """Web SSO:""", """ Authentication successful""" ]
  Fields = [
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]+)""", 
    """(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-\.]+))\s{1,100}(Juniper|PulseSecure):""",
    """PulseSecure:.+?({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s{1,100}\-\s{1,100}({host}[\w\-.]+)""",
    """PulseSecure:.*?\[({src_ip}[a-fA-F:\d.]+)\]\s{1,100}(({domain}[^\\]+)\\)?(?:({user_email}[^@\s]+@[^@\s]+)|({user}[^\s]+))\(({realm}[^\)]+)?""",
  ]
  DupFields = [ "host->dest_host" ]
}
```