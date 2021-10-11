#### Parser Content
```Java
{
Name = q-kiteworks-file-read
  Product = Kiteworks
  Conditions = [ """Viewed file""", """Activity:""", """File: id=""" ]
  Fields = ${KiteWorksParserTemplates.q-kiteworks-file-activity.Fields}[
    """({accesses}View(ed)?) file (({file_name}[^,]{1,2000}\.({file_ext}[^\s,\.]{1,2000})))[^:]{1,2000}?File:"""
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