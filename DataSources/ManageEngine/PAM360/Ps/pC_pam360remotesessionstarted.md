#### Parser Content
```Java
{
Name = pam360-remote-session-started
  DataType = "remote-logon"
  Conditions= [ """Session_Started""", """Success""", """RDP_initiated_from_PAM360_to_""" ]
  Fields = ${ManageEngineParserTemplates.pam360-app-activity.Fields}[
    """({event_name}Session_Started)""",
    """\sResourceAudit:({user}[^:]{1,2000}):({src_ip}[A-Fa-f:\d\.]{1,2000})""",
    """RDP_initiated_from_PAM360_to_({dest_ip}[A-Fa-f:\d\.]{1,2000})""",
    """ResourceAudit:({user}[^:]{1,200}):({src_ip}[a-fA-F:\d\.]{1,200})"""
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