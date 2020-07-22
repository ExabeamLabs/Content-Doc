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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\WAttack ID:\s*({attack_id}[^;\s]+);""",
    """\WAttack Name:\s*({alert_name}[^;]+);""",
    """\WResult Status:\s*(?:n\/a|({outcome}[^;]+));""",
    """\WAdmin Domain:\s*({domain}[^;]+);""",
    """\WSensor Name:\s*({sensor}[^;]+);""",
    """\WAttack Time:\s*({time}\d+\-\d+\-\d+ \d+:\d+:\d+ \w+)""",
    """\WInterface:\s*({interface}[^;]+);""",
    """\WDirection:\s*({direction}[^;]+);""",
    """Direction:\s*Outbound;.*?SIP:\s*({src_ip}[A-Fa-f:\d.]+);\s*SPort:\s*(?:N/A|({src_port}\d+));\s*DIP:\s*({dest_ip}[A-Fa-f:\d.]+);\s*DPort:\s*(?:N/A|({dest_port}\d+));""",
    """Direction:\s*Inbound;.*?SIP:\s*({dest_ip}[A-Fa-f:\d.]+);\s*SPort:\s*(?:N/A|({dest_port}\d+));\s*DIP:\s*({src_ip}[A-Fa-f:\d.]+);\s*DPort:\s*(?:N/A|({src_port}\d+));""",
    """\WApp Proto:\s*(?:N/A|({app_protocol}[^;]+));""",
    """\WNet Proto:\s*({protocol}[^;]+);""",
    """\WAlert ID:\s*({alert_id}\d+)""",
    """\WAlert Type:\s*({alert_type}[^;]+);""",
    """\WAttack Severity:\s*({alert_severity}[^;]+);""",
    """\WAttack Conf:\s*({attack_conf}[^;]+);""",
    """\WCat:\s*({category}[^;]+);""",
    """\WSub-Cat:\s*({sub_category}[^;]+);""",
    """\WDetection Mech:\s*({detection_mech}[^;]+);"""
  ]
}
```