#### Parser Content
```Java
{
Name = f5-network-alert-3
  Vendor = F5 Networks
  Product = WAF F5
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ type = waf,""", """,attack_type = """, """,violations = """, """,policy_name = """ ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """date_time\s*=\s*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """dest_ip\s*=\s*({dest_ip}[A-Fa-f:\d.]+)""",
    """dest_port\s*=\s*({dest_port}\d+)""",
    """policy_name\s*=\s*(|({alert_name}[^,]+)),""",
    """violations\s*=\s*(|({alert_name}[^,]+)),""",
    """ip_client\s*=\s*({src_ip}[A-Fa-f:\d.]+)""",
    """protocol\s*=\s*({protocol}[^,]+)""",
    """request_status\s*=\s*({outcome}[^,]+)""",
    """severity\s*=\s*({alert_severity}[^,]+)""",
    """src_port\s*=\s*({src_port}\d+)""",
    """username\s*=\s*(N\/A|({user}[^\s,>]+)),""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```