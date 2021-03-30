#### Parser Content
```Java
{
Name = moveit-file-delete
  DataType = "file-delete"
  Conditions = [ """AgentBrand: MOVEit""", """Delete File"""]
  Fields = ${MoveITParserTemplates.moveit-activity.Fields} [
     """\sFileID:\s*({file_id}[^,]+)""",
     """\sFileName:\s*({file_name}[^,]+)""",
     """\sFolderPath:\s*({file_path}[^,]+)""",
     """\sXFerSize:\s*({bytes}[^,]+)""",
  ]
}
moveit-activity = {
  Vendor = IPSwitch
  Product = MoveIt DMZ
  Lms = Syslog
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)"""
    """<\d+>\w+\s\d\d\s\d\d:\d\d:\d\d\s({host}[^\s]+)"""
    """\sUsername:\s*({username}[^,]+)""",
    """\sIPAddress:\s*({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """User\s'({domain}[^']+)'\s\(({username}[^\)]+)\).*?:\s({activity}[^,]+)"""
  ]

```