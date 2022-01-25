#### Parser Content
```Java
{
Name = postfix-dlp-email-from
  Vendor = Postfix
  Product = Postfix
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """postfix""", """from=<""", """nrcpt=""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d:(\+|-)\d{1,100})\s<"""
    """({host}[\w.\-]{1,2000}) postfix""",
    """({msg_id}[^\s"]{1,2000}): from=<({sender}[^@>]{1,2000}?@[^>]{1,2000}?)>""",
    """\ssize=({bytes}\d{1,100})""",
    """\snrcpt=({num_recipients}\d{1,100})""",
    """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"host(_name)?":"({host}[^"]{1,2000})""",
  ]


}
```