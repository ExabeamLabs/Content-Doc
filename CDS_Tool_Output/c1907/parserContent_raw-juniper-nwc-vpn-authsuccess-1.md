#### Parser Content
```Java
{
Name = raw-juniper-nwc-vpn-authsuccess-1
  Vendor = Juniper Networks
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  """ PulseSecure:""", """Web SSO:""", """ Authentication successful""" ]
  Fields = [
    """exabeam_host=(.+?@\s*)?({host}[^\s]+)""", 
    """(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-\.]+))\s+(Juniper|PulseSecure):""",
    """PulseSecure:.+?({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s+\-\s+({host}[\w\-.]+)""",
    """PulseSecure:.*?\[({src_ip}[a-fA-F:\d.]+)\]\s+(({domain}[^\\]+)\\)?(?:({user_email}[^@\s]+@[^@\s]+)|({user}[^\s]+))\(({realm}[^\)]+)?""",
  ]
  DupFields = [ "host->dest_host" ]
}
```