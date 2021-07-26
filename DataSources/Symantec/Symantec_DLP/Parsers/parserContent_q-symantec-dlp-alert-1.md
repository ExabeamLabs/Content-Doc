#### Parser Content
```Java
{
Name = q-symantec-dlp-alert-1
  Vendor = Symantec
  Product = Symantec DLP
  Lms = QRadar
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """LEEF:""", """|Symantec|DLP|""", """Corporate Network""" ]
  Fields = [
    """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)[\+\-]\d{1,100}:\d{1,100}\s""",
    """\s({host}[\w\-.]{1,2000})\s{1,100}LEEF:""",
    """LEEF:([^\|]{0,2000}\|){3}({alert_severity}\d{1,100})""",
    """LEEF:([^\|]{0,2000}\|){4}(N\/A)*.*?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """({alert_name}(On|Off) the Corporate Network)""",
    """\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(AM|PM|am|pm)\s{0,100}HTTP\s{0,100}({malware_url}[^\s]{1,2000})""",
    """\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(AM|PM|am|pm)\s{0,100}(N\/A)*\s{0,100}((N\/A)|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\s{0,100}({dest_host}\w\w\-\w+\d\d{1,100})""",
  ]
}
```