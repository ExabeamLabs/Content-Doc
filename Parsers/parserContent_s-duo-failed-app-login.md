#### Parser Content
```Java
{
Name = s-duo-failed-app-login
  Vendor = Cisco
  Product = Duo Access Security
  Lms = Splunk
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSZ"
  Conditions = [ """"action": "admin_login_error"""", """error\"""", """"username": """, """"description": """" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d(\+|\-)\d+)""",
    """exabeam_host=({host}[^\s]+)""",
    """"username":\s*"({user_fullname}[^"]+)""",
    """"username":\s*"({user_firstname}\S+)\s+({user_lastname}[^\s"\\]+)""",
    """"action":\s*"({activity}[^"]+)"""",
    """"object":\s*"({object}[^"]+)"""",
    """"email\\"+:\s*\\"+({user_email}[^"]+?)\\"+""",
    """"ip_address\\"+:\s*\\"+({src_ip}[^"]+?)\\"+""",
    """"error\\"+:\s*\\"+({failure_reason}[^"]+?)\\"+"""
  ]
}
```