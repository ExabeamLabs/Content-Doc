#### Parser Content
```Java
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
        """\d{1,100}:\d{1,100}:\d{1,100}(.\d{1,100})?\s({host}[^\s]+)""",
	"""remoteuser-({user}[^\]]+)""",
	"""From-({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
	"""({outcome}Success)"""
  ]
}
```