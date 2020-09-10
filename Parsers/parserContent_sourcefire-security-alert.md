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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+\s+\d+\s+\d\d:\d\d:\d\d \d\d\d\d \w+)""",
    """\[({alert_name}\d+:\d+:\d+)\]""",
    """\[Classification:\s*({alert_type}[^\]]+)\]""",
    """\[Priority:\s*({alert_severity}\d+)\] \{({protocol}[^\}]+)\}""",
    """\[\d+:\d+:\d+\]\s+\\*"({additional_info}[^"]+?)\\*"""",
    """\{\w+\}\s*({src_ip}[^\s]+?)\:+({src_port}\d+) \((unknown|({src_country}[^\)]+))""",
    """->\s*({dest_ip}[^\s]+?)\:+({dest_port}\d+) \((unknown|({dest_country}[^\)]+))""",
    """\[Impact:\s*(Unknown|({impact}[^\]]+))""",
    """ From \\"({src_host}[\w\-.]+)\\""",
  ]
}
```