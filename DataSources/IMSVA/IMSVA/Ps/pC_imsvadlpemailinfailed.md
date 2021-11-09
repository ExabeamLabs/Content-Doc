#### Parser Content
```Java
{
Name = imsva-dlp-email-in-failed
  Vendor = IMSVA
  Product = IMSVA
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy/MM/dd HH:mm:ss Z"
  Conditions = [ """ imsva""" , """#null#""", """QuarantineTransac"""]
  Fields = [
    """\s({host}imsva\d{1,100}\s{1,100}[\w.\-]{1,2000})""",
    """({time}\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d (\+|\-)\d\d:\d\d)\t+([^\t]{1,2000})(\t+[^\t]{1,2000}){3,4}\t+({sender}[^\t@]{1,2000}@[^\t@;]{1,2000})\t+(({recipients}({recipient}[^\t@;]{1,2000}@[^\t@;]{1,2000})[^\t]{0,2000})\t+)?\s{0,100}(|({subject}[^\t]{1,2000}?))\s{0,100}\t+(#null#|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\t+(.+?\[({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\])?""",
    """\s({bytes}\d{1,100})\s{1,100}bytes in """,
    """\d\d\d\d \w+ \d\d \d\d:\d\d:\d\d (\+|\-)\d\d:\d\d\s{1,100}\d{1,100}\s{1,100}({attachments}({attachment}[^\s;]{1,2000})(;\s{1,100}[^;]{1,2000})*?)\s{0,100}$""",
  ]
  DupFields = [ "sender->external_address" ]
}
}
```