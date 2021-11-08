#### Parser Content
```Java
{
Name = proofpoint-m15
  Vendor = Proofpoint
  Product = Proofpoint DLP
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """mod=dmarc cmd=run""", """header.from""" ]
  Fields = [
    """"{1,20}host"{1,20}:"{1,20}({host}[^"]{1,2000})""",
    """"@timestamp"{1,20}:"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)"{1,20}"""
    """\sx=({xid}.+?)\s{1,100}(\w+=|$)""",
    """\sheader.from=({sender}.*?@[^"]{1,2000})""",
  ]
}
```