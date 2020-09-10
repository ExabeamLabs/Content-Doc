#### Parser Content
```Java
{
Name = cisco-fpr-113004
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "yyyy MMM dd HH:mm:ss"
  Conditions = [ """%FTD-auth-6-113004:""" ]
  Fields = [
    """exabeam_host=(.+?@\s*)?({host}[\w.\-]+)""",
    """({time}\d+ \w+ \d+ \d+:\d+:\d+)""",
    """%FTD-\w+?-?({priority}\d+)-({event_code}\d+)""",
    """-113004:\s+({event_name}AAA user authentication Successful)""",
    """ user\s*=? ({user}[^\s]+)""",
    """server =\s+({dest_ip}[A-Za-z\d.:]+)"""
    ]
}



{
  Name = cisco-authentication-successful
  Vendor = Cisco
  Product = ACI
  Lms = Syslog
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["""ACI""","""login,session""","""Success"""]
  Fields = [
        """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
        """\d+:\d+:\d+(.\d+)?\s({host}[^\s]+)""",
	"""remoteuser-({user}[^\]]+)""",
	"""From-({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
	"""({outcome}Success)"""
  ]
}
```