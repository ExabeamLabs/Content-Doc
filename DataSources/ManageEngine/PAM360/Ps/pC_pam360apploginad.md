#### Parser Content
```Java
{
Name = pam360-app-login-ad
  DataType = "app-login"
  Conditions= [ """User_Logged_in_-_AD""", """Success""" ]
  Fields = ${ManageEngineParserTemplates.pam360-app-activity.Fields}[
    """({activity}User_Logged_in_-_AD)""",
    """\sResourceAudit:({user}[^:]{1,2000}):({src_ip}[A-Fa-f:\d\.]{1,2000})""",
    """RDP_initiated_from_PAM360_to_({dest_ip}[A-Fa-f:\d\.]{1,2000})""",
    """Success\s[\w\-\.]{1,200}\s\-({user}[^:]{1,200})""",
    """({app}PAM360)"""
]    


pam360-app-activity = {
  Vendor = ManageEngine
  Product = PAM360
  Lms = Direct
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Fields = [
    """\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d\s{1,100}({host}[\w\-.]{1,2000})""",
    """({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """({outcome}Success)""",
    ]
 
}
```