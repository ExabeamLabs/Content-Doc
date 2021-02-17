#### Parser Content
```Java
{
Name = cisco-config-change-1
  Vendor = Cisco
  Product = ACI
  Lms = Syslog
  DataType = "config-change"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["""ACI""","""modified by""","""New: information"""]
  Fields = [
        """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
	"""\d+:\d+:\d+(.\d+)?\s({host}[^\s]+)""",
	"""remoteuser-({user}[^,\s]+)""",
	"""info\].+?\s({additional_info}.+?)\s*$"""
  ]
}
```