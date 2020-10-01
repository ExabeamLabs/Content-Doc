#### Parser Content
```Java
{
Name = s-duo-app-activity
  Vendor = Cisco
  Product = Duo Access Security
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSZ"
  Conditions = [ """"action": """", """"object": """, """"username": """, """"description": """" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d(\+|\-)\d+)""",
    """exabeam_host=({host}[^\s]+)""",
    """"action":\s*"({activity}[^"]+)"""",
    """"object":\s*"({object}[^"]+)"""",
    """"description":\s*"\{({additional_info}.+?)\}""",
    """"username":\s*"({user_fullname}[^"]+)""",
    """"username":\s*"({user_firstname}\S+)\s+({user_lastname}[^\s"\\]+)""",
    """"realname\\"+:\s*\\"+({user_fullname}.+?)\\"+(,\s+|$)""",
    """"realname\\"+:\s*\\"+({user_firstname}\S+)\s+({user_lastname}[^\s\\]+)""",
    """"uname\\"+:\s*\\"+({user}[^"]+?)\\"+""",
    """"email\\"+:\s*\\"+({user_email}[^"]+?)\\"+""",
    """"ip_address\\"+:\s*\\"+({src_ip}[^"]+?)\\"+"""
  ]
}
```