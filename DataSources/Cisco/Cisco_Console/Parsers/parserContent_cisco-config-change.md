#### Parser Content
```Java
{
Name = cisco-config-change
  Vendor = Cisco
  Product = Cisco Console
  Lms = Splunk
  DataType = "config-change"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "%SYS-", "Configured from console" ]
  Fields = [
		"""exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
		"""exabeam_host=({host}[^\s]+)""",
		"""\d\d:\d\d:\d\d (?:-|({host}[^:\s]+)) \d{1,100}: """,
		"""({event_code}%SYS-[^\s]+):"""
		"""({log_type}CONFIG)""",
		"""%SYS-[^\s]+: ({event_name}.+?)\s{0,100}$""",
		"""Configured from console by ({user}.+?) on """,
		""" on .+?\((({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^)]+))\)"""
  	   ]
}
```