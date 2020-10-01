#### Parser Content
```Java
{
Name = swivel-authentication-failed
  Vendor = Swivel
  Product = Swivel
  Lms = Splunk
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [""" INFO """, """ PINsafe[""", """]: """, """failed"""]
  Fields = [
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """user[:\s]*({user}[^\s.,]+)""",
    """({app}PINsafe)""",
    """\d\d:\d\d:\d\d\s({host}[a-fA-F\d.:]+)""",
    """INFO\s*(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).+?({outcome}failed)[^"]+)""",
    """error:\s({failure_reason}.+?)\s*$""",
	]
}
```