#### Parser Content
```Java
{
Name = snort-alert
  Vendor = Snort
  Product = Snort
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """snort:""","""Classification:""" ]
  Fields = [
     """exabeam_time=({time}\d+-\d+-\d+ \d+:\d+:\d+)""",
     """exabeam_host=({host}[\w.\-]+)""",
     """snort:\s*\[({alert_id}[^\]]+?)\]\s*({alert_name}[^\[]+?)\s*\[Classification""",
     """({alert_name}snort: \d+:\d+:\d+)""",
     """Classification: ({alert_type}[^\]]+?)\]?\s*\[?Priority: ({alert_severity}\d+)""",
     """snort: \d+:\d+:\d+ ({additional_info}[^:]+?) Classification:""",
     """(<({src_interface}[^<>]*?)>)? \{({protocol}\w+)\} ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\:({src_port}\d+)""",
     """(<({src_interface}[^<>]*?)>)? \{({protocol}\w+)\} ({src_port}\d+):({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
     """-> ({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\:({dest_port}\d+)""",
     """-> ({dest_port}\d+):({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
}
```