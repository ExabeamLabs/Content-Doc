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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """date_time\s{0,100}=\s{0,100}({time}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d)""",
    """ip_intelligence_policy_name\s{0,100}=\s{0,100}(|({alert_name}[^,]{1,2000})),""",
    """ip_intelligence_threat_name\s{0,100}=\s{0,100}(|({alert_name}[^,]{1,2000})),""",
    """source_ip\s{0,100}=\s{0,100}({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """ip_protocol\s{0,100}=\s{0,100}({protocol}[^,]{1,2000})""",
    """severity\s{0,100}=\s{0,100}({alert_severity}[^,]{1,2000})""",
    """source_port\s{0,100}=\s{0,100}({src_port}\d{1,100})""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```