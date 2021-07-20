#### Parser Content
```Java
{
Name = swivel-authentication-success
  Vendor = Swivel
  Product = Swivel
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [""" INFO """, """ PINsafe[""", """]: """, """successful"""]
  Fields = [
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """user[:\s]{0,2000}({user}[^\s.,]{1,2000})""",
    """({app}PINsafe)""",
    """\d\d:\d\d:\d\d\s({host}[a-fA-F\d.:]{1,2000})""",
    """INFO\s{0,100}({additional_info}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).+?({outcome}successful).+?)\.?\s{0,100}$""",
	]
}
```