#### Parser Content
```Java
{
Name = mcafee-ips-network-alert
  Vendor = McAfee
  Product = McAfee Network Security Platform (IPS)
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss z"
  Conditions = [ """SyslogAlertForwarder:""", """Attack Name:""", """Sensor Name:""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\WAttack ID:\s{0,100}({attack_id}[^;\s]{1,2000});""",
    """\WAttack Name:\s{0,100}({alert_name}[^;]{1,2000});""",
    """\WResult Status:\s{0,100}(?:n\/a|({outcome}[^;]{1,2000}));""",
    """\WAdmin Domain:\s{0,100}({domain}[^;]{1,2000});""",
    """\WSensor Name:\s{0,100}({sensor}[^;]{1,2000});""",
    """\WAttack Time:\s{0,100}({time}\d{1,100}\-\d{1,100}\-\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \w+)""",
    """\WInterface:\s{0,100}({interface}[^;]{1,2000});""",
    """\WDirection:\s{0,100}({direction}[^;]{1,2000});""",
    """Direction:\s{0,100}Outbound;.*?SIP:\s{0,100}({src_ip}[A-Fa-f:\d.]{1,2000});\s{0,100}SPort:\s{0,100}(?:N/A|({src_port}\d{1,100}));\s{0,100}DIP:\s{0,100}({dest_ip}[A-Fa-f:\d.]{1,2000});\s{0,100}DPort:\s{0,100}(?:N/A|({dest_port}\d{1,100}));""",
    """Direction:\s{0,100}Inbound;.*?SIP:\s{0,100}({dest_ip}[A-Fa-f:\d.]{1,2000});\s{0,100}SPort:\s{0,100}(?:N/A|({dest_port}\d{1,100}));\s{0,100}DIP:\s{0,100}({src_ip}[A-Fa-f:\d.]{1,2000});\s{0,100}DPort:\s{0,100}(?:N/A|({src_port}\d{1,100}));""",
    """\WApp Proto:\s{0,100}(?:N/A|({app_protocol}[^;]{1,2000}));""",
    """\WNet Proto:\s{0,100}({protocol}[^;]{1,2000});""",
    """\WAlert ID:\s{0,100}({alert_id}\d{1,100})""",
    """\WAlert Type:\s{0,100}({alert_type}[^;]{1,2000});""",
    """\WAttack Severity:\s{0,100}({alert_severity}[^;]{1,2000});""",
    """\WAttack Conf:\s{0,100}({attack_conf}[^;]{1,2000});""",
    """\WCat:\s{0,100}({category}[^;]{1,2000});""",
    """\WSub-Cat:\s{0,100}({sub_category}[^;]{1,2000});""",
    """\WDetection Mech:\s{0,100}({detection_mech}[^;]{1,2000});"""
  ]
}
```