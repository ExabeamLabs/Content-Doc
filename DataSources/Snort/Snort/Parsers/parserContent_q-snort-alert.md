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
     """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
     """\d\d:\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})\s\w+:""",
     """(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\s{0,100}\d\d\s{0,100}:\d\d \d{1,100} \w+)""",
     """\[\s{0,100}({alert_name}\d{1,100}:\d{1,100}:\d{1,100})\]""",
     """\[Classification:\s{0,100}({alert_type}[^\]]{1,2000})\]""",
     """\[Priority:\s{0,100}({alert_severity}\d{1,100})\]""",
     """\[\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\]\s{1,100}"({additional_info}[^"]{1,2000})"""",
     """ From "(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^"\s]{1,2000}))""",
     """\{\w+\}\s{0,100}({src_ip}[^\s]{1,2000}?)\:+({src_port}\d{1,100})""",
     """->\s{0,100}({dest_ip}[^\s]{1,2000}?)\:+({dest_port}\d{1,100})""",
     """\[Impact:\s{0,100}(Unknown|({impact}[^\]]{1,2000}))""",
  ]
}
```