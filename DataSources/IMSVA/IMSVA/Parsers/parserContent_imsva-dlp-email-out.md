#### Parser Content
```Java
{
Name = imsva-dlp-email-out
  Vendor = IMSVA
  Product = IMSVA
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy/MM/dd HH:mm:ss Z"
  Conditions = [ """ imsva""" , """: queued as""" , """sent"""]
  Fields = [
    """\s({host}imsva\d{1,100}\s{1,100}[\w.\-]+)""",
    """({time}\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d (\+|\-)\d\d:\d\d)\t+([^\t]+)(\t+[^\t]+){3,4}\t+({sender}[^\t@]+@[^\t@]+)\t+(({recipients}({recipient}[^\t@;]+@({external_domain}[^\t@;]+))[^\t]*)\t+)?\s{0,100}(|({subject}[^\t]+?))\s{0,100}\t+(#null#|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\t+(.+?\[({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\])?""",
    """\s({bytes}\d{1,100})\s{1,100}bytes in """,
    """\d\d\d\d \w+ \d\d \d\d:\d\d:\d\d (\+|\-)\d\d:\d\d\s{1,100}(?!\d\d\d\d \w+ \d\d)\d{1,100}\s{1,100}({attachments}({attachment}[^.]+\.({file_ext}[^\s;]+))(;\s{1,100}[^;]+?)*?)\s{0,100}$""",
  ]
  DupFields = [ "recipient->external_address" ]
}
```