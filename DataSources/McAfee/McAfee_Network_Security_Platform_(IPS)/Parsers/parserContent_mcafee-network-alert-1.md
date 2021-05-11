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
    """\|Time:\s{0,100}({time}[^\|]+)""",
    """\|Device:\s{0,100}({host}[\w\-.]+)\|""",
    """\|Name:\s{0,100}({protocol}[^\s:\|]+):\s{0,100}({alert_name}[^\|]+)""",
    """\|Category:\s{0,100}({alert_type}[^\|]+)""",
    """\|Severity:\s{0,100}({alert_severity}[^\|]+)""",
    """\|Application Protocol:\s{0,100}((?i)(n\/a)|({app_protocol}[^\|]+))""",
    """\|Destination IP:\s{0,100}({dest_ip}[A-Fa-f:\d.]+)""",
    """\|Destination Port:\s{0,100}({dest_port}\d{1,100})""",
    """\|Source IP:\s{0,100}({src_ip}[A-Fa-f:\d.]+)""",
    """\|Source Port:\s{0,100}({src_port}\d{1,100})""",
    """Result:\s{0,100}((?i)(n\/a)|({outcome}[^\|]+))""",
  ]
}
```