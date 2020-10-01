#### Parser Content
```Java
{
Name = secureauth-system-session-start
  Vendor = SecureAuth
  Product = SecureAuth Login
  Lms = QRadar
  DataType = "authentication-successful"
  TimeFormat = "MMM dd yyyy HH:mm:ss.SSS"
  Conditions = [ """LEEF:""", """|SecureAuth|""", """resource=Session - Start""" ]
  Fields = [
    """devTime=({time}\w{3}\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d.\d\d\d)""",
    """exabeam_host=({host}[^\s]+)""",
    """cat=({category}[^\s]+)""",
    """usrName=({user}[^\s]+)""",
    """processId=({pid}\d+)""",
    """src=({src_ip}[A-Fa-f:\d.]+)""",
    """dst=({dest_ip}[A-Fa-f:\d.]+)""",
    """url=({domain}[^\s]+)""",
    """sev=({severity}\d+)""",
    """resource=({event_name}.+?)(\s+\w+=|\s*$)""",
  ]
}
```