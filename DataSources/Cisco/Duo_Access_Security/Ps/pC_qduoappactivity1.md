#### Parser Content
```Java
{
Name = q-duo-app-activity-1
  Product = Duo Access Security
  Conditions = [ """action=send_enroll_code;""", """object=""", """timestamp=""" ]

q-duo-app-activity = {
  Vendor = Cisco
  Lms = QRadar
  DataType = "app-activity"
  TimeFormat = "MM/dd/yyyy HH:mm:ss"
  Fields = [
    """\d\d:\d\d\s{1,100}({host}.+?)\s{1,100}(\S+\s{1,100})*@\{action=({activity}[^;]{1,2000})""",
    """username=(?![^:]{1,2000}:\s{0,100}[^;\}]{1,2000})({user_fullname}[^;\}]{1,2000})""",
    """"uname"{1,20}:\s{0,100}"{1,2}({user}[^"]{1,2000}?)"{1,20},""",
    """"realname"{1,20}:\s{0,100}"{1,2}({user_fullname}[^"]{1,2000}?)"{1,20},""",
    """object=\s{0,100}({object}[^;]{1,2000}?)(?:;|\})""",
    """timestamp=\s{0,100}({time}\d{1,100}\/\d{1,100}\/\d\d\d\d \d\d:\d\d:\d\d)""",
    """"email"{1,20}:\s{0,100}"{1,2}({user_email}[^@]{1,2000}@({email_domain}[^"]{1,2000}?))"{1,20},""",
    """"ip_address"{1,20}:\s{0,100}"{1,20}({src_ip}[a-fA-F\d.:]{1,2000})"""",
    """"primary_auth_method"{1,20}:\s{0,100}"{1,2}({auth_method}[^"]{1,2000}?)"{1,20},""",
    """"factor"{1,20}:\s{0,100}"{1,2}({action}[^"]{1,2000}?)"{1,20},""",
  
}
```