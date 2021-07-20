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
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d(\+|\-)\d{1,100})""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"action":\s{0,100}"({activity}[^"]{1,2000})"""",
    """"object":\s{0,100}"({object}[^"]{1,2000})"""",
    """"description":\s{0,100}"\{({additional_info}.+?)\}""",
    """"username":\s{0,100}"({user_fullname}[^"]{1,2000})""",
    """"username":\s{0,100}"({user_firstname}\S+)\s{1,100}({user_lastname}[^\s"\\]{1,2000})""",
    """"realname\\"{1,20}:\s{0,100}\\"{1,20}({user_fullname}.+?)\\"{1,20}(,\s{1,100}|$)""",
    """"realname\\"{1,20}:\s{0,100}\\"{1,20}({user_firstname}\S+)\s{1,100}({user_lastname}[^\s\\]{1,2000})""",
    """"uname\\"{1,20}:\s{0,100}\\"{1,20}({user}[^"]{1,2000}?)\\"{1,20}""",
    """"email\\"{1,20}:\s{0,100}\\"{1,20}({user_email}[^"]{1,2000}?)\\"{1,20}""",
    """"ip_address\\"{1,20}:\s{0,100}\\"{1,20}({src_ip}[^"]{1,2000}?)\\"{1,20}"""
  ]
}
```