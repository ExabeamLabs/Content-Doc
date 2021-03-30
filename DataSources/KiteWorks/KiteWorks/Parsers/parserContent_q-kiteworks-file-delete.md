#### Parser Content
```Java
{
Name = q-kiteworks-file-delete
  Conditions = [ """Deleted folder""", """Activity:""" ]
  Fields = ${KiteWorksParserTemplates.q-kiteworks-file-activity.Fields}[
    """({accesses}Deleted) folder "+({file_name}[^"]+)"""",
  ]
}
q-kiteworks-file-activity = {
    Vendor = KiteWorks
    Lms = QRadar
    DataType = "file-operations"
    IsHVF = true
    TimeFormat = "epoch"
    Fields = [
      """\w+\s+\d+ \d+:\d+:\d+\s+({host}[\w.\-]+)\s+""",
      """({host}[\w.\-]+)\s+rest_server.py:""",
      """exabeam_endTime=({time}\d+)""",
      """\ssize=({bytes}\d+)""",
      """({user_email}[^@\s]+@[^\s]+)\s+id=[^,]+,\s*({src_ip}[a-fA-F\d.:]+),\s*Activity:""",
      """Activity:\s*({activity}.+?)\."*\s*$""",
    ]

```