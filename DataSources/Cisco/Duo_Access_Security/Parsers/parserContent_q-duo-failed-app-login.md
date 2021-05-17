#### Parser Content
```Java
{
Name = q-duo-failed-app-login
  Vendor = Cisco
  Product = Duo Access Security
  Lms = QRadar
  DataType = "failed-app-login"
  TimeFormat = "MM/dd/yyyy HH:mm:ss"
  Conditions = [ """action=admin_login_error;""", """username=""", """description=""" ]
  Fields = [
    """\d\d:\d\d\s{1,100}({host}.+?)\s{1,100}(\S+\s{1,100})*@\{action=({activity}[^;]{1,2000})""",
    """timestamp=\s{0,100}({time}\d{1,100}\/\d{1,100}\/\d\d\d\d \d\d:\d\d:\d\d)""",
    """({app}DUO)""",
    """username=({user_fullname}[^;\}]{1,2000})""",
    """username=({user_firstname}[^;\}\s]{1,2000})\s{1,100}({user_lastname}[^;\}]{1,2000})""",
    """object=\s{0,100}({object}[^;]{1,2000}?)(?:;|\})""",
    """"email"{1,20}:\s{0,100}"{1,2}({user_email}[^"]{1,2000}?)"{1,20}
```