#### Parser Content
```Java
{
Name = mcafee-network-alert-1
  Vendor = McAfee
  Product = McAfee Network Security Platform (IPS)
  DataType = "network-alert"
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd HH:mm:ss zzz"
  Conditions = [ """|Name:""" , """|Category:""", """|Application Protocol:""", """: Result:""" ]
  Fields = [
    """\|Time:\s*({time}[^\|]+)""",
    """\|Device:\s*({host}[\w\-.]+)\|""",
    """\|Name:\s*({protocol}[^\s:\|]+):\s*({alert_name}[^\|]+)""",
    """\|Category:\s*({alert_type}[^\|]+)""",
    """\|Severity:\s*({alert_severity}[^\|]+)""",
    """\|Application Protocol:\s*((?i)(n\/a)|({app_protocol}[^\|]+))""",
    """\|Destination IP:\s*({dest_ip}[A-Fa-f:\d.]+)""",
    """\|Destination Port:\s*({dest_port}\d+)""",
    """\|Source IP:\s*({src_ip}[A-Fa-f:\d.]+)""",
    """\|Source Port:\s*({src_port}\d+)""",
    """Result:\s*((?i)(n\/a)|({outcome}[^\|]+))""",
  ]
}
```