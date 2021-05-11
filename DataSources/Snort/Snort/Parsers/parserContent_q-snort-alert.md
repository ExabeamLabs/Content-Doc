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
     """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
     """\d\d:\d\d:\d\d\s{1,100}({host}[^\s]+)\s\w+:""",
     """(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\s{0,100}\d\d\s{0,100}:\d\d \d{1,100} \w+)""",
     """\[\s{0,100}({alert_name}\d{1,100}:\d{1,100}:\d{1,100})\]""",
     """\[Classification:\s{0,100}({alert_type}[^\]]+)\]""",
     """\[Priority:\s{0,100}({alert_severity}\d{1,100})\]""",
     """\[\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\]\s{1,100}"({additional_info}[^"]+)"""",
     """ From "(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^"\s]+))""",
     """\{\w+\}\s{0,100}({src_ip}[^\s]+?)\:+({src_port}\d{1,100})""",
     """->\s{0,100}({dest_ip}[^\s]+?)\:+({dest_port}\d{1,100})""",
     """\[Impact:\s{0,100}(Unknown|({impact}[^\]]+))""",
  ]
}
```