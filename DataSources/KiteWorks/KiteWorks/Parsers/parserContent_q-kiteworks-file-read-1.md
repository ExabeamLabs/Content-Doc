#### Parser Content
```Java
{
Name = q-kiteworks-file-read-1
  Product = KiteWorks
  Conditions = [ """View file""", """Activity:""" ]
  Fields = ${KiteWorksParserTemplates.q-kiteworks-file-activity.Fields}[
    """\s({accesses}View) file\s+({file_name}.+?(\.({file_ext}\w+)))(\s+from email.|\.\s+File:)""",
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
      """({user_email}[^@\s]+@({email_domain}[^\s]+))\s+id=[^,]+,\s*({src_ip}[a-fA-F\d.:]+),\s*Activity:""",
      """Activity:\s*({activity}.+?)\."*\s*$""",
    ]

```