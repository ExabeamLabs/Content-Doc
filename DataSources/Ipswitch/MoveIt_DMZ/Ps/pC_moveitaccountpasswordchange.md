#### Parser Content
```Java
{
Name = moveit-account-password-change
  DataType = "password-change"
  Conditions = [ """MOVEitDMZ""", """Change User Password"""]
  Fields = ${MoveITParserTemplates.moveit-activity.Fields} [
     """TargetName:\s{1,100}({target_user}[^,]{1,2000})""",
     """TargetID:\s{1,100}({target_user_sid}[^,]{1,2000})""",
     """({activity}Change User Password)"""
  ]
}
moveit-activity = {
  Vendor = Ipswitch
  Product = MoveIt DMZ
  Lms = Syslog
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)"""
    """\s\d\d:\d\d:\d\d\s({host}[^\s]{1,2000})""",
    """\sIPAddress:\s{0,100}({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """User\s'(({user_email}[^@]{1,2000}@[^']{1,2000})|Automation|({user_fullname}[^']{1,2000}))?'\s\(({user}[^\)]{1,2000})?\)""",
    """\s:\s{1,100}({activity}[^,]{1,2000}),\s{1,100}ID:""",
    """\sUsername:\s{0,100}(Automation|({user}[^,]{1,2000}))"""
  ]

```