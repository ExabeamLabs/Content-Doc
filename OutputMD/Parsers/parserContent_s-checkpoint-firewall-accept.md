#### Parser Content
```Java
{
Name = s-checkpoint-firewall-accept
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = Splunk
  DataType = "network-connection"
  IsHVF = true
  TimeFormat = "dMMMyyyy HH:mm:ss"
  Conditions = [ """|product=VPN-1 & FireWall-1""", """|i/f_name=""", """|action=accept""" ]
  Fields = [
    """\|time=\s*({time}\d+\w+\d\d\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w-.]+)""",
    """\|orig=({host}[^\|]+)\|""",
    """\|service=({app_protocol}[^\|]+)\|""",
    """\|action=({action}[^\|]+)\|""",
    """\|rule_name=({rule}[^\|]+)\|""",
    """\|src=(?:({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^\|]+))\|""",
    """\|s_port=({src_port}\d+)""",
    """\|dst=(?:({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^\|]+))\|""",
    """\|proto=({protocol}[^\|]+)\|""",
    """\|xlatesport=({src_translated_port}\d+)""",
    """\|xlatedport=({dest_translated_port}\d+)"""
  ]
}
```