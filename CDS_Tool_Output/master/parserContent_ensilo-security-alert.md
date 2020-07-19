#### Parser Content
```Java
{
Name = ensilo-security-alert
  Vendor = EnSilo
  Product = EnSilo
  Lms = Direct
  DataType = "alert"
  TimeFormat = "dd-MMM-yyyy', 'HH:mm:ss"
  Conditions = [ """ enSilo """, """;Raw Data ID:""", """;Rules List:""", """;Severity:""" ]
  Fields = [
    """\s({host}[\w\-.]+)\s+enSilo""",
    """\WFirst Seen:\s*({time}\d+-\w+-\d+,\s*\d+:\d+:\d+)""",
    """\WEvent ID:\s*({event_code}[^;]+)""",
    """\WRaw Data ID:\s*({alert_id}[^;]+)""",
    """\WDevice Name:\s*({src_host}[\w\-.]+)""",
    """\WProcess Name:\s*({process_name}[^;]+)""",
    """\WProcess Path:\s*({process}[^;]+)""",
    """\WProcess Type:\s*({process_type}[^;]+)""",
    """\WSeverity:\s*({alert_severity}[^;]+)""",
    """\WClassification:\s*({category}[^;]+)""",
    """\WRules List:\s*({alert_type}[^;]+)""",
    """\WDestination:\s*(({dest_ip}[A-Fa-f:\d.]+)|({alert_type}[^;]+));""",
    """\WAction:\s*({outcome}[^;]+)""",
    """\WCount:\s*({rule_count}[^;]+)""",
    """\WRules List:\s*({alert_name}[^;]+)""",
    """\WUsers:\s*(({domain}[^\\\s;]+)\\+)({user}[^\\\s;]+)""",
    """\WMAC Address:\s*({src_mac}[^;,\s]+)""",
  ]
}
```