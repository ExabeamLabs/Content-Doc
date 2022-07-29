#### Parser Content
```Java
{
Name = duo-app-activity-14
  Conditions = [ """ duo: """, """|user_create|""", """": """" ]

duo-app-activity-3 = {
  Vendor = Cisco
  Product = Duo Access Security
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """:\d\d\|({user_fullname}[^\|]{0,2000})\|(|({target_user}[^\|]{1,2000}))\|({activity}[^\|]{1,2000})\|""",
    """"email":\s{0,20}"({user_email}[^@"]{1,2000}@({email_domain}[^"\s]{1,2000}))"""",
    """({app}duo)"""
  
}
```