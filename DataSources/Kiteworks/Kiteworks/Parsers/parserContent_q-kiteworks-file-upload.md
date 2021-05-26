#### Parser Content
```Java
{
Name = q-kiteworks-file-upload
  Product = Kiteworks
  Conditions = [ """Uploaded file""", """Activity:""", """File: id=""" ]
  Fields = ${KiteWorksParserTemplates.q-kiteworks-file-activity.Fields}[
    """({accesses}Uploaded) file ({file_name}.+?(\.({file_ext}\w+))?)\.\s{0,100}File:""",
    """({accesses}Uploaded) file "{1,20}({file_name}[^"]{1,2000}?(\.({file_ext}\w+))?)"""",
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