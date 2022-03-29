#### Parser Content
```Java
{
Name = hp-ilo-app-login-2
  Conditions = [ """XML login: """, """ILO""" ]
  Fields = ${HPEParserTemplates.hp-ilo-app-login.Fields} [
    """({event_name}XML login)"""
  ]

hp-ilo-app-login = {
    Vendor = HP
    Product = HP iLO
    Lms = Syslog
    DataType = "app-login"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
      """\d\d:\d\d:\d\dZ\s({host}[^\s]{1,2000})\s\#ILO""",
      """({app}ILO)""",
      """\slogin:\s({user}[^\s]{1,2000})""",
      """\slogin:\s(\S+\s){2}({src_ip}[a-fA-F\d:.]{1,2000})\(({src_host}[^\)]{1,2000})\)"""
    ]
    DupFields = ["host->dest_host"
}
```