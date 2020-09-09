#### Parser Content
```Java
{
Name = stealthwatch-network-alert
  Vendor = Cisco
  Product = Cisco StealthWatch (Lancope)
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """StealthWatch""", """|target_hostname""", """|alarm_severity_id""", """|alarm_type_description""" ]
  Fields = [
    """({host}[\w\-.]+) StealthWatch""",
    """\Wtime(=|\|)({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """\|target_hostname(=|\|)(|({dest_host}[^|]+))\|""",
    """\|alarm_type_description(=|\|)({additional_info}[^|]+)\|""",
    """\|port(=|\|)({dest_port}\d+)""",
    """\|target_ip(=|\|)({dest_ip}[a-fA-F\d.:]+)""",
    """\|target_mac_address(=|\|)({dest_mac}[a-fA-F\d.:]+)""",
    """\|alarm_type_name(=|\|)({alert_name}[^|]+)\|""",
    """\|alarm_category_name(=|\|)({alert_type}[^|]+)(\||\s$)""",
    """\|source_hostname(=|\|)(|({src_host}[^|]+))\|""",
    """\|alarm_severity_id(=|\|)({alert_severity}[^|]+)\|""",
    """\|source_ip(=|\|)({src_ip}[a-fA-F\d.:]+)""",
    """\|source_mac_address(=|\|)({src_mac}[a-fA-F\d.:]+)""",
    """\|source_username(=|\|)(|({user}[^|\s]+)) details""",
    """\|device_ip(=|\|)({host_ip}[a-fA-F\d.:]+)""",
    """\|device_name(=|\|)({host}[^|]+)\|""",
    """\|details(=|\|)(|({details}[^|]+))\|""",
    """\|protocol(=|\|)(|({protocol}[^|\s]+?))\s*\|""",
    """\|alarm_id(=|\|)({alert_id}[^|]+)\|"""
  ]
}
```