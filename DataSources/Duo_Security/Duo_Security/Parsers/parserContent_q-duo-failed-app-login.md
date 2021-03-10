#### Parser Content
```Java
{
Name = q-duo-failed-app-login
  Vendor = Duo Security
  Lms = QRadar
  DataType = "failed-app-login"
  TimeFormat = "MM/dd/yyyy HH:mm:ss"
  Conditions = [ """action=admin_login_error;""", """username=""", """description=""" ]
  Fields = [
    """\d\d:\d\d\s+({host}.+?)\s+(\S+\s+)*@\{action=({activity}[^;]+)""",
    """timestamp=\s*({time}\d+\/\d+\/\d\d\d\d \d\d:\d\d:\d\d)""",
    """({app}DUO)""",
    """username=({user_fullname}[^;\}]+)""",
    """username=({user_firstname}[^;\}\s]+)\s+({user_lastname}[^;\}]+)""",
    """object=\s*({object}[^;]+?)(?:;|\})""",
    """"email"+:\s*"{1,2}({user_email}[^"]+?)"+,""",
    """"ip_address"+:\s*"+({src_ip}[a-fA-F\d.:]+)"""",
    """"error"+:\s*"{1,2}({failure_reason}[^"]+?)"+,""",
  ]
}
```