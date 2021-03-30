#### Parser Content
```Java
{
Name = imsva-dlp-email-in
  Vendor = IMSVA
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy/MM/dd HH:mm:ss Z"
  Conditions = [ """ imsva""" , """Queued mail for delivery""", """sent"""]
  Fields = [
    """\s({host}imsva\d+\s+[\w.\-]+)""",
    """({time}\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d (\+|\-)\d\d:\d\d)\t+([^\t]+)(\t+[^\t]+){3,4}\t+({sender}[^\t@]+@({external_domain}[^\t@;]+))\t+(({recipients}({recipient}[^\t@;]+@[^\t@;]+)[^\t]*)\t+)?\s*(|({subject}[^\t]+?))\s*\t+(#null#|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\t+(.+?\[({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\])?""",
    """\s({bytes}\d+)\s+bytes in """,
    """\d\d\d\d \w+ \d\d \d\d:\d\d:\d\d (\+|\-)\d\d:\d\d\s+\d+\s+({attachments}({attachment}[^\s;]+)(;\s+[^;]+)*?)\s*$""",
  ]
  DupFields = [ "sender->external_address" ]
}
```