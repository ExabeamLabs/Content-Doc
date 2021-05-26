#### Parser Content
```Java
{
Name = microsoft-remote-desktop
  Vendor = Microsoft
  Product = Web Application Proxy
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Microsoft-Windows-TerminalServices-Gateway""", """connected to resource""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """on client computer "{1,20}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """connected to resource "{1,20}(?:({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^"]{1,2000}))""",
    """The user "{1,20}({domain}[^\\]{1,2000})?(\\)?({user}[^"]{1,2000})""",
    """Connection protocol used: "{1,20}({protocol}[^"]{1,2000})"""
  ]
}
```