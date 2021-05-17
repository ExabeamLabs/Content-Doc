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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """cat=({category}[^\s]{1,2000})""",
    """usrName=({user}[^\s]{1,2000})""",
    """processId=({pid}\d{1,100})""",
    """src=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """dst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """url=({domain}[^\s]{1,2000})""",
    """sev=({severity}\d{1,100})""",
    """resource=({event_name}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
  ]
}
```