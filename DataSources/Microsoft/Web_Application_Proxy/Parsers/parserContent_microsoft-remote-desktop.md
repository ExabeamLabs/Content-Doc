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
    """exabeam_host=({host}[\w.\-]+)""",
    """on client computer "{1,20}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """connected to resource "{1,20}(?:({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^"]+))""",
    """The user "{1,20}({domain}[^\\]+)?(\\)?({user}[^"]+)""",
    """Connection protocol used: "{1,20}({protocol}[^"]+)"""
  ]
}
```