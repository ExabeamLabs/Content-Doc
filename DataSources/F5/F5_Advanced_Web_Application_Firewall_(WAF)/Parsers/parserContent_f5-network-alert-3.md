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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """date_time\s{0,100}=\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """dest_ip\s{0,100}=\s{0,100}({dest_ip}[A-Fa-f:\d.]+)""",
    """dest_port\s{0,100}=\s{0,100}({dest_port}\d{1,100})""",
    """policy_name\s{0,100}=\s{0,100}(|({alert_name}[^,]+)),""",
    """violations\s{0,100}=\s{0,100}(|({alert_name}[^,]+)),""",
    """ip_client\s{0,100}=\s{0,100}({src_ip}[A-Fa-f:\d.]+)""",
    """protocol\s{0,100}=\s{0,100}({protocol}[^,]+)""",
    """request_status\s{0,100}=\s{0,100}({outcome}[^,]+)""",
    """severity\s{0,100}=\s{0,100}({alert_severity}[^,]+)""",
    """src_port\s{0,100}=\s{0,100}({src_port}\d{1,100})""",
    """username\s{0,100}=\s{0,100}(N\/A|({user}[^\s,>]+)),""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```