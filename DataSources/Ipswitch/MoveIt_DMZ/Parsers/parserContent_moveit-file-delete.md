#### Parser Content
```Java
{
Name = moveit-file-delete
  DataType = "file-delete"
  Conditions = [ """AgentBrand: MOVEit""", """Delete File"""]
  Fields = ${MoveITParserTemplates.moveit-activity.Fields} [
     """\sFileID:\s{0,100}({file_id}[^,]+)""",
     """\sFileName:\s{0,100}({file_name}[^,]+)""",
     """\sFolderPath:\s{0,100}({file_path}[^,]+)""",
     """\sXFerSize:\s{0,100}({bytes}[^,]+)""",
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