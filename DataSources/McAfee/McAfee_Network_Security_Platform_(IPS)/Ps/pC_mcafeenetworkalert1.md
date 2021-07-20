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
    """\|Time:\s{0,100}({time}[^\|]{1,2000})""",
    """\|Device:\s{0,100}({host}[\w\-.]{1,2000})\|""",
    """\|Name:\s{0,100}({protocol}[^\s:\|]{1,2000}):\s{0,100}({alert_name}[^\|]{1,2000})""",
    """\|Category:\s{0,100}({alert_type}[^\|]{1,2000})""",
    """\|Severity:\s{0,100}({alert_severity}[^\|]{1,2000})""",
    """\|Application Protocol:\s{0,100}((?i)(n\/a)|({app_protocol}[^\|]{1,2000}))""",
    """\|Destination IP:\s{0,100}({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\|Destination Port:\s{0,100}({dest_port}\d{1,100})""",
    """\|Source IP:\s{0,100}({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\|Source Port:\s{0,100}({src_port}\d{1,100})""",
    """Result:\s{0,100}((?i)(n\/a)|({outcome}[^\|]{1,2000}))""",
  ]
}
```