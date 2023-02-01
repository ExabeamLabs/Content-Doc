#### Parser Content
```Java
{
Name = pam360-remote-session-ended
  DataType = "app-activity"
  Conditions= [ """Session_Ended""", """Success""", """RDP_initiated_from_""", """has_stopped""" ]
  Fields = ${ManageEngineParserTemplates.pam360-app-activity.Fields}[
    """({activity}Session_Ended)""",
    """RDP_initiated_from_PAM360_to_({dest_ip}[A-Fa-f:\d\.]{1,200})""",
    """ResourceAudit:({user}[^:]{1,200}):({src_ip}[a-fA-F:\d\.]{1,200})""",
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