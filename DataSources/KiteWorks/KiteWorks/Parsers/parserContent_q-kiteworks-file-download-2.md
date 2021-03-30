#### Parser Content
```Java
{
Name = q-kiteworks-file-download-2
  Product = KiteWorks
  Conditions = [ """Downloaded """, """Activity:""" ]
  Fields = ${KiteWorksParserTemplates.q-kiteworks-file-activity.Fields}[
    """\sDownloaded (file|attachment)\s+({file_name}.+?(\.({file_ext}\w+)))\.\s+(Subject|File):""",
    """({accesses}Downloaded)""",
    """with Files:\s*({file_name}[^,]+?(\.({file_ext}\w+))?.*?)\.\s*$""",
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