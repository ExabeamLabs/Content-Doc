#### Parser Content
```Java
{
Name = q-snort-alert
  Vendor = Snort
  Product = Snort
  Lms = QRadar
  DataType = "alert"
  TimeFormat = "MMM dd HH:mm:ss yyyy z"
  Conditions = [ """[Classification:""", """[Priority:""", """[Impact:""" ]
  Fields = [
     """exabeam_host=([^=]+@\s*)?({host}\S+)""",
     """\d\d:\d\d:\d\d\s+({host}[^\s]+)\s\w+:""",
     """(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+\s+\d+\s+\d\d:\s*\d\d\s*:\d\d \d+ \w+)""",
     """\[\s*({alert_name}\d+:\d+:\d+)\]""",
     """\[Classification:\s*({alert_type}[^\]]+)\]""",
     """\[Priority:\s*({alert_severity}\d+)\]""",
     """\[\s*\d+:\d+:\d+\]\s+"({additional_info}[^"]+)"""",
     """ From "(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^"\s]+))""",
     """\{\w+\}\s*({src_ip}[^\s]+?)\:+({src_port}\d+)""",
     """->\s*({dest_ip}[^\s]+?)\:+({dest_port}\d+)""",
     """\[Impact:\s*(Unknown|({impact}[^\]]+))""",
  ]
}
```