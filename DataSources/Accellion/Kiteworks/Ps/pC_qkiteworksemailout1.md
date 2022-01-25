#### Parser Content
```Java
{
Name = q-kiteworks-email-out-1
  Product = Kiteworks
  Conditions = [ """Activity: Created draft""", """with files""" ]

q-kiteworks-email = {
  Vendor = Accellion
  Lms = QRadar
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """\w+\s{1,100}\d{1,100} \d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[\w.\-]{1,2000})\s{1,100}""",
    """exabeam_endTime=({time}\d{1,100})""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({user_email}[^@\s]{1,2000}@[^\s]{1,2000})\s{1,100}id=[^,]{1,2000},\s{0,100}({src_ip}[a-fA-F\d.:]{1,2000}),\s{0,100}Activity:""",
    """\sSubject:\s{0,100}"{0,20}\s{0,100}({subject}[^"]{1,2000})\s{0,100}"{0,20}""",
    """\sTo:\s{0,100}({recipients}.+?)\s{0,100}with files \[({attachments}.+?)\]""",
    """\sTo:\s{0,100}({recipient}[^,@]{1,2000}@({external_domain}[^\s,]{1,2000}))""",

  ]
  DupFields = [ "recipient->external_address", "user_email->sender" 
}
```