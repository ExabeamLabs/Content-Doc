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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """\WAttack ID:\s{0,100}({attack_id}[^;\s]+);""",
    """\WAttack Name:\s{0,100}({alert_name}[^;]+);""",
    """\WResult Status:\s{0,100}(?:n\/a|({outcome}[^;]+));""",
    """\WAdmin Domain:\s{0,100}({domain}[^;]+);""",
    """\WSensor Name:\s{0,100}({sensor}[^;]+);""",
    """\WAttack Time:\s{0,100}({time}\d{1,100}\-\d{1,100}\-\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \w+)""",
    """\WInterface:\s{0,100}({interface}[^;]+);""",
    """\WDirection:\s{0,100}({direction}[^;]+);""",
    """Direction:\s{0,100}Outbound;.*?SIP:\s{0,100}({src_ip}[A-Fa-f:\d.]+);\s{0,100}SPort:\s{0,100}(?:N/A|({src_port}\d{1,100}));\s{0,100}DIP:\s{0,100}({dest_ip}[A-Fa-f:\d.]+);\s{0,100}DPort:\s{0,100}(?:N/A|({dest_port}\d{1,100}));""",
    """Direction:\s{0,100}Inbound;.*?SIP:\s{0,100}({dest_ip}[A-Fa-f:\d.]+);\s{0,100}SPort:\s{0,100}(?:N/A|({dest_port}\d{1,100}));\s{0,100}DIP:\s{0,100}({src_ip}[A-Fa-f:\d.]+);\s{0,100}DPort:\s{0,100}(?:N/A|({src_port}\d{1,100}));""",
    """\WApp Proto:\s{0,100}(?:N/A|({app_protocol}[^;]+));""",
    """\WNet Proto:\s{0,100}({protocol}[^;]+);""",
    """\WAlert ID:\s{0,100}({alert_id}\d{1,100})""",
    """\WAlert Type:\s{0,100}({alert_type}[^;]+);""",
    """\WAttack Severity:\s{0,100}({alert_severity}[^;]+);""",
    """\WAttack Conf:\s{0,100}({attack_conf}[^;]+);""",
    """\WCat:\s{0,100}({category}[^;]+);""",
    """\WSub-Cat:\s{0,100}({sub_category}[^;]+);""",
    """\WDetection Mech:\s{0,100}({detection_mech}[^;]+);"""
  ]
}
```