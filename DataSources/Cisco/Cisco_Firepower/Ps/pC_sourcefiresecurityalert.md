#### Parser Content
```Java
{
Name = sourcefire-security-alert
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = Direct
  DataType = "alert"
  TimeFormat = "MMM dd HH:mm:ss yyyy z"
  Conditions = [ """[Classification:""", """[Priority:""", """[Impact:""", """message":"[""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d \d\d\d\d \w+)""",
    """\[({alert_name}\d{1,100}:\d{1,100}:\d{1,100})\]""",
    """\[Classification:\s{0,100}({alert_type}[^\]]{1,2000})\]""",
    """\[Priority:\s{0,100}({alert_severity}\d{1,100})\] \{({protocol}[^\}]{1,2000})\}""",
    """\[\d{1,100}:\d{1,100}:\d{1,100}\]\s{1,100}\\*"({additional_info}[^"]{1,2000}?)\\*"""",
    """\{\w+\}\s{0,100}({src_ip}[^\s]{1,2000}?)\:+({src_port}\d{1,100}) \((unknown|({src_country}[^\)]{1,2000}))""",
    """->\s{0,100}({dest_ip}[^\s]{1,2000}?)\:+({dest_port}\d{1,100}) \((unknown|({dest_country}[^\)]{1,2000}))""",
    """\[Impact:\s{0,100}(Unknown|({impact}[^\]]{1,2000}))""",
    """ From \\"({src_host}[\w\-.]{1,2000})\\""",
  ]


}
```