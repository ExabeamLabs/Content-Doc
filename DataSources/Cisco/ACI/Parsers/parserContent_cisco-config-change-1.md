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
	"""\d{1,100}:\d{1,100}:\d{1,100}(.\d{1,100})?\s({host}[^\s]{1,2000})""",
	"""remoteuser-({user}[^,\s]{1,2000})""",
	"""info\].+?\s({additional_info}.+?)\s{0,100}$"""
  ]
}
```