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
     """exabeam_time=({time}\d{1,100}-\d{1,100}-\d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
     """exabeam_host=({host}[\w.\-]+)""",
     """snort:\s{0,100}\[({alert_id}[^\]]+?)\]\s{0,100}({alert_name}[^\[]+?)\s{0,100}\[Classification""",
     """({alert_name}snort: \d{1,100}:\d{1,100}:\d{1,100})""",
     """Classification: ({alert_type}[^\]]+?)\]?\s{0,100}\[?Priority: ({alert_severity}\d{1,100})""",
     """snort: \d{1,100}:\d{1,100}:\d{1,100} ({additional_info}[^:]+?) Classification:""",
     """(<({src_interface}[^<>]*?)>)? \{({protocol}\w+)\} ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\:({src_port}\d{1,100})""",
     """(<({src_interface}[^<>]*?)>)? \{({protocol}\w+)\} ({src_port}\d{1,100}):({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
     """-> ({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\:({dest_port}\d{1,100})""",
     """-> ({dest_port}\d{1,100}):({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
}
```