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
    """\s({host}imsva\d{1,100}\s{1,100}[\w.\-]+)""",
    """({time}\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d (\+|\-)\d\d:\d\d)\t+([^\t]+)(\t+[^\t]+){3,4}\t+({sender}[^\t@]+@({external_domain}[^\t@;]+))\t+(({recipients}({recipient}[^\t@;]+@[^\t@;]+)[^\t]*)\t+)?\s{0,100}(|({subject}[^\t]+?))\s{0,100}\t+(#null#|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\t+(.+?\[({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\])?""",
    """\s({bytes}\d{1,100})\s{1,100}bytes in """,
    """\d\d\d\d \w+ \d\d \d\d:\d\d:\d\d (\+|\-)\d\d:\d\d\s{1,100}\d{1,100}\s{1,100}({attachments}({attachment}[^\s;]+)(;\s{1,100}[^;]+)*?)\s{0,100}$""",
  ]
  DupFields = [ "sender->external_address" ]
}
```