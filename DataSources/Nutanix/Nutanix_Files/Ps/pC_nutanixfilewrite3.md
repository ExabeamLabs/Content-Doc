#### Parser Content
```Java
{
Name = nutanix-file-write-3
  DataType = "file-write"
  Conditions = ["""|DirectoryCreate|success|""", """ SMB["""]
  Fields = ${NutanixFilesParserTemplates.nutanixfiles-events.Fields} [
    """({user_sid}[^|]{1,2000})\|({src_ip}[A-Fa-f\d:.]{1,2000})\|({event_name}DirectoryCreate)\|({outcome}success)"""
  ]

nutanixfiles-events = {
    Vendor = Nutanix
    Product = Nutanix Files
    Lms = Direct
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """SMB\[[^]]{1,2000}\]:[^\\]{1,2000}\\({domain}[^\\]{1,2000})\\({user}[^(|]{1,2000})""",
      """SMB\[[^\|]{1,2000}\|([^\|]{0,2000}\|){4}({file_path}({file_parent}[^|]{1,2000})\/({file_name}[^\|\/]{1,2000}?(\.({file_ext}[^\|\.]{1,2000}))?))\|""",
      """\d\d:\d\d:\d\d\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}SMB\[""",
    
}
```