#### Parser Content
```Java
{
Name = stealthwatch-network-alert
  Vendor = Cisco
  Product = Cisco Secure Network Analytics
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """StealthWatch""", """|target_hostname""", """|alarm_severity_id""", """|alarm_type_description""" ]
  Fields = [
    """({host}[\w\-.]{1,2000}) StealthWatch""",
    """\Wtime(=|\|)({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """\|target_hostname(=|\|)(|({dest_host}[^|]{1,2000}))\|""",
    """\|alarm_type_description(=|\|)({additional_info}[^|]{1,2000})\|""",
    """\|port(=|\|)({dest_port}\d{1,100})""",
    """\|target_ip(=|\|)({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\|target_mac_address(=|\|)({dest_mac}[a-fA-F\d.:]{1,2000})""",
    """\|alarm_type_name(=|\|)({alert_name}[^|]{1,2000})\|""",
    """\|alarm_category_name(=|\|)({alert_type}[^|]{1,2000})(\||\s$)""",
    """\|source_hostname(=|\|)(|({src_host}[^|]{1,2000}))\|""",
    """\|alarm_severity_id(=|\|)({alert_severity}[^|]{1,2000})\|""",
    """\|source_ip(=|\|)({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\|source_mac_address(=|\|)({src_mac}[a-fA-F\d.:]{1,2000})""",
    """\|source_username(=|\|)(|({user}[^|\s]{1,2000})) details""",
    """\|device_ip(=|\|)({host_ip}[a-fA-F\d.:]{1,2000})""",
    """\|device_name(=|\|)({host}[^|]{1,2000})\|""",
    """\|details(=|\|)(|({details}[^|]{1,2000}))\|""",
    """\|protocol(=|\|)(|({protocol}[^|\s]{1,2000}?))\s{0,100}\|""",
    """\|alarm_id(=|\|)({alert_id}[^|]{1,2000})\|"""
  ]
}
```