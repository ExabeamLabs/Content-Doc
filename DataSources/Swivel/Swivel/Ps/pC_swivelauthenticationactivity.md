#### Parser Content
```Java
{
Name = swivel-authentication-activity
  Vendor = Swivel
  Product = Swivel
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [""" INFO """, """ PINsafe[""", """]: """]
  Fields = [
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """user[:\s]{0,2000}({user}[^\s.,]{1,2000})""",
    """({app}PINsafe)""",
    """\d\d:\d\d:\d\d\s({host}[a-fA-F\d.:]{1,2000})""",
    """INFO\s{0,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{1,100}(-\s{1,100})?({activity}.+?)\s{0,100}$""",
    """({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({src_port}\d{1,100})\s{1,100}({activity}.+?)\s{0,100}$"""
	]
}
```