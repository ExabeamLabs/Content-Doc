#### Parser Content
```Java
{
Name = f5-network-alert-4
  Vendor = F5
  Product = F5 IP Intelligence
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """ type = ipi,""", """,attack_type = """, """,ip_intelligence_threat_name = """, """,ip_intelligence_policy_name = """ ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """date_time\s*=\s*({time}\w+\s+\d+\s+\d+\s+\d\d:\d\d:\d\d)""",
    """ip_intelligence_policy_name\s*=\s*(|({alert_name}[^,]+)),""",
    """ip_intelligence_threat_name\s*=\s*(|({alert_name}[^,]+)),""",
    """source_ip\s*=\s*({src_ip}[A-Fa-f:\d.]+)""",
    """ip_protocol\s*=\s*({protocol}[^,]+)""",
    """severity\s*=\s*({alert_severity}[^,]+)""",
    """source_port\s*=\s*({src_port}\d+)""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```