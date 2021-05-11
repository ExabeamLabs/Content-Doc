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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d \d\d\d\d \w+)""",
    """\[({alert_name}\d{1,100}:\d{1,100}:\d{1,100})\]""",
    """\[Classification:\s{0,100}({alert_type}[^\]]+)\]""",
    """\[Priority:\s{0,100}({alert_severity}\d{1,100})\] \{({protocol}[^\}]+)\}""",
    """\[\d{1,100}:\d{1,100}:\d{1,100}\]\s{1,100}\\*"({additional_info}[^"]+?)\\*"""",
    """\{\w+\}\s{0,100}({src_ip}[^\s]+?)\:+({src_port}\d{1,100}) \((unknown|({src_country}[^\)]+))""",
    """->\s{0,100}({dest_ip}[^\s]+?)\:+({dest_port}\d{1,100}) \((unknown|({dest_country}[^\)]+))""",
    """\[Impact:\s{0,100}(Unknown|({impact}[^\]]+))""",
    """ From \\"({src_host}[\w\-.]+)\\""",
  ]
}
```