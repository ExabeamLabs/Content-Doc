#### Parser Content
```Java
{
Name = q-symantec-dlp-email-out
  Vendor = Symantec
  Product = Symantec DLP
  Lms = QRadar
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """LEEF:""", """|Symantec|DLP|""", """SMTP""", """Off the Corporate Network""" ]
  Fields = [
    """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)[\+\-]\d{1,100}:\d{1,100}\s""",
    """\s({host}[\w\-.]+)\s{1,100}LEEF:""",
    """LEEF:([^\|]*\|){4}(N\/A)*\s{0,100}({user_lastname}[^\\\/,\_\s]+?),\s{0,100}({user_firstname}[^\\\/,\_]+?)\s{1,100}\w+\s{1,100}({file_name}[^\s]+)""",
    """\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(AM|PM|am|pm)\s{0,100}SMTP\s{0,100}({recipients}({recipient}[^\\\/\s@,;"]+@({external_domain}[^\\\/\s@,;"]+))[^\s]*?)November""",
    """\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(AM|PM|am|pm)\s{0,100}N\/A\s{0,100}({sender}[^\\\/\s@,;"]+@[^\\\/\s@,;"]+?)\s{0,100}({dest_host}\w\w\-\w+\d\d{1,100})\s{0,100}(|({subject}.*?))\s{0,100}(N\/A)+""",
    """\|N\/AN\/A((N\/A)|(null)|({file_name}(?!null|N\/A).+?))\snull"""
  ]
  DupFields = [ "recipient->external_address" ]
}
```