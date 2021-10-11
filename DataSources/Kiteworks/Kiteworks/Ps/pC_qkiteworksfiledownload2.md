#### Parser Content
```Java
{
Name = q-kiteworks-file-download-2
  Product = Kiteworks
  Conditions = [ """Downloaded """, """Activity:""" ]
  Fields = ${KiteWorksParserTemplates.q-kiteworks-file-activity.Fields}[
    """\sDownloaded (file|attachment)\s{1,100}({file_name}.+?(\.({file_ext}\w+)))\.\s{1,100}(Subject|File):""",
    """({accesses}Downloaded)""",
    """with Files:\s{0,100}({file_name}[^,]{1,2000}?(\.({file_ext}\w+))?.*?)\.\s{0,100}$""",
  ]
}
q-kiteworks-file-activity = {
    Vendor = Accellion
    Lms = QRadar
    DataType = "file-operations"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """\w+\s{1,100}\d{1,100} \d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[\w.\-]{1,2000})\s{1,100}""",
      """({host}[\w.\-]{1,2000})\s{1,100}rest_server.py:""",
      """exabeam_endTime=({time}\d{1,100})""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """\ssize=({bytes}\d{1,100})""",
      """({user_email}[^@\s]{1,2000}@({email_domain}[^\s]{1,2000}))\s{1,100}id=[^,]{1,2000},\s{0,100}({src_ip}[a-fA-F\d.:]{1,2000}),\s{0,100}Activity:?""",
      """Activity:\s{0,100}({activity}.+?)\."{0,20}\s{0,100}$""",
      """Activity Type:\s{1,100}({activity}[^\s,]{1,2000})"""
    ]

```