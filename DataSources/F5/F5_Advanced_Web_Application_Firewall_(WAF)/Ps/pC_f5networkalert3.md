#### Parser Content
```Java
{
Name = f5-network-alert-3
  Vendor = F5
  Product = F5 Advanced Web Application Firewall (WAF)
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ type = waf,""", """,attack_type = """, """,violations = """, """,policy_name = """ ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """date_time\s{0,100}=\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """dest_ip\s{0,100}=\s{0,100}({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """dest_port\s{0,100}=\s{0,100}({dest_port}\d{1,100})""",
    """policy_name\s{0,100}=\s{0,100}(|({alert_name}[^,]{1,2000})),""",
    """violations\s{0,100}=\s{0,100}(|({alert_name}[^,]{1,2000})),""",
    """ip_client\s{0,100}=\s{0,100}({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """protocol\s{0,100}=\s{0,100}({protocol}[^,]{1,2000})""",
    """request_status\s{0,100}=\s{0,100}({outcome}[^,]{1,2000})""",
    """severity\s{0,100}=\s{0,100}({alert_severity}[^,]{1,2000})""",
    """src_port\s{0,100}=\s{0,100}({src_port}\d{1,100})""",
    """username\s{0,100}=\s{0,100}(N\/A|({user}[^\s,>]{1,2000})),""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```