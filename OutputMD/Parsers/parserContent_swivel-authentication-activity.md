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
    """user[:\s]*({user}[^\s.,]+)""",
    """({app}PINsafe)""",
    """\d\d:\d\d:\d\d\s({host}[a-fA-F\d.:]+)""",
    """INFO\s*({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(-\s+)?({activity}.+?)\s*$""",
    """({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({src_port}\d+)\s+({activity}.+?)\s*$"""
	]
}
```