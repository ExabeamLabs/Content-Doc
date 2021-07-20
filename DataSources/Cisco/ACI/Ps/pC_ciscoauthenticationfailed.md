#### Parser Content
```Java
{
Name = cisco-authentication-failed
  Vendor = Cisco
  Product = ACI
  Lms = Syslog
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["""ACI""","""login,session""","""Failure"""]
  Fields = [
        """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
	"""\d{1,100}:\d{1,100}:\d{1,100}(.\d{1,100})?\s({host}[^\s]{1,2000})""",
	"""From-({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
	"""({outcome}Failure)"""
  ]
}
```