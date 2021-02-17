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
    """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)[\+\-]\d+:\d+\s""",
    """\s({host}[\w\-.]+)\s+LEEF:""",
    """LEEF:([^\|]*\|){4}(N\/A)*\s*({user_lastname}[^\\\/,\_\s]+?),\s*({user_firstname}[^\\\/,\_]+?)\s+\w+\s+({file_name}[^\s]+)""",
    """\d+:\d+:\d+\s+(AM|PM|am|pm)\s*SMTP\s*({recipients}({recipient}[^\\\/\s@,;"]+@({external_domain}[^\\\/\s@,;"]+))[^\s]*?)November""",
    """\d+:\d+:\d+\s+(AM|PM|am|pm)\s*N\/A\s*({sender}[^\\\/\s@,;"]+@[^\\\/\s@,;"]+?)\s*({dest_host}\w\w\-\w+\d\d+)\s*(|({subject}.*?))\s*(N\/A)+""",
    """\|N\/AN\/A((N\/A)|(null)|({file_name}(?!null|N\/A).+?))\snull"""
  ]
  DupFields = [ "recipient->external_address" ]
}
```