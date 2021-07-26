#### Parser Content
```Java
{
Name = s-duo-failed-app-login-1
  Vendor = Cisco
  Product = Duo Access Security
  Lms = Splunk
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSZ"
  Conditions = [ """"action": "admin_2fa_error"""", """error\"""", """"username": """, """"description": """" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d(\+|\-)\d{1,100})""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"username":\s{0,100}"({user_fullname}[^"]{1,2000})""",
    """"username":\s{0,100}"({user_firstname}\S+)\s{1,100}({user_lastname}[^\s"\\]{1,2000})""",
    """"action":\s{0,100}"({activity}[^"]{1,2000})"""",
    """"object":\s{0,100}"({object}[^"]{1,2000})"""",
    """"email\\"{1,20}:\s{0,100}\\"{1,20}({user_email}[^"]{1,2000}?)\\"{1,20}""",
    """"ip_address\\"{1,20}:\s{0,100}\\"{1,20}({src_ip}[^"]{1,2000}?)\\"{1,20}""",
    """"error\\"{1,20}:\s{0,100}\\"{1,20}({failure_reason}[^"]{1,2000}?)\\"{1,20}"""
  ]
}
```