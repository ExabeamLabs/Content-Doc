#### Parser Content
```Java
{
Name = moveit-member-added-1
  DataType = "member-added"
  Conditions = [ """MOVEitDMZ""", """Add User"""]
  Fields = ${MoveITParserTemplates.moveit-activity.Fields} [
     """TargetName:\s{1,100}({target_user}[^,]+)""",
     """TargetID:\s{1,100}({target_user_sid}[^,]+)""",
     """({activity}Add User)""",
     """\sID:\s({account_id}\d{1,100})""",
  ]
}
moveit-activity = {
  Vendor = Ipswitch
  Product = MoveIt DMZ
  Lms = Syslog
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)"""
    """\s\d\d:\d\d:\d\d\s({host}[^\s]+)""",
    """\sIPAddress:\s{0,100}({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """User\s'(({user_email}[^@]+@[^']+)|Automation|({user_fullname}[^']+))?'\s\(({user}[^\)]+)?\)""",
    """\s:\s{1,100}({activity}[^,]+),\s{1,100}ID:""",
    """\sUsername:\s{0,100}(Automation|({user}[^,]+))"""
  ]

```