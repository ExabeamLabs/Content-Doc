#### Parser Content
```Java
{
Name = s-checkpoint-alert-4
  Vendor = Check Point Software
  Product = Check Point Endpoint Security
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """|product=SmartDefense|""", """|action=monitor|""" ]
  Fields = [
    """date=({time}\d+);""",
    """exabeam_host=({host}[\w-.]+)""",
    """\|Protection Name=({alert_name}[^\|]+)\|""",
    """\|Attack Info=({alert_type}[^\|]+)\|""",
    """\|Severity=({alert_severity}[^\|]+)\|""",
    """\|src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\|s_port=({src_port}\d+)""",
    """\|dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\|service=({dest_port}\d+)""",
    """\|src_country=(?:Internal|({src_country}[^\|]+))\|""",
    """\|dst_country=(?:Other|({dst_country}[^\|]+))\|""",
    """\|src_user_name=[^(]+\(({user}[^)]+)""",
    """\|user=[^(]+\(({user}[^)]+)""" 
  ]
}
```