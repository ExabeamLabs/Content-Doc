#### Parser Content
```Java
{
Name = moveit-ssh-login-failed
  DataType = "authentication-failed"
  Conditions = [ """AgentBrand: MOVEit""", """FAILED: SSH"""]
  Fields = ${MoveITParserTemplates.moveit-activity.Fields} [
     """\sMessage:\s{0,100}({failure_reason}[^,\.]{1,2000})""",
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