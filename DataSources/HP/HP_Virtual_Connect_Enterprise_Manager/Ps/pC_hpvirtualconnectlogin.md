#### Parser Content
```Java
{
Name = hp-virtual-connect-login
  Vendor = HP
  Product = HP Virtual Connect Enterprise Manager
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """vcmd:""", """VCM user login :""" ]
  Fields = [
     """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
     """\d\d:\d\d:\d\d\s({host}\S+)\svcmd:""",
     """VCM user login : ({auth_type}\w+)\s({domain}[^\\]{1,2000})\\({user}[^@]{1,2000})@({src_ip}[A-Fa-f:\d.]{1,2000})""",
     """({event_name}user login)""",
     """({app}VCM)"""
  ]
}
```