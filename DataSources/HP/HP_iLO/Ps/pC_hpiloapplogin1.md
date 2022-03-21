#### Parser Content
```Java
{
Name = hp-ilo-app-login-1
  Conditions = [ """Browser login: """, """ILO""" ]
  Fields = ${HPEParserTemplates.hp-ilo-app-login.Fields} [
    """({event_name}Browser login)"""
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
      """\slogin:\s(\S+\s){2}({src_ip}[a-fA-F\d:.]{1,2000})\(({dest_host}[^\)]{1,2000})\)"""
    
}
```