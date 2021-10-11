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
    """\s({host}[\w\-.]{1,2000})\s{1,100}enSilo""",
    """\WFirst Seen:\s{0,100}({time}\d{1,100}-\w+-\d{1,100},\s{0,100}\d{1,100}:\d{1,100}:\d{1,100})""",
    """\WEvent ID:\s{0,100}({event_code}[^;]{1,2000})""",
    """\WRaw Data ID:\s{0,100}({alert_id}[^;]{1,2000})""",
    """\WDevice Name:\s{0,100}({src_host}[\w\-.]{1,2000})""",
    """\WProcess Name:\s{0,100}({process_name}[^;]{1,2000})""",
    """\WProcess Path:\s{0,100}({process}[^;]{1,2000})""",
    """\WProcess Type:\s{0,100}({process_type}[^;]{1,2000})""",
    """\WSeverity:\s{0,100}({alert_severity}[^;]{1,2000})""",
    """\WClassification:\s{0,100}({category}[^;]{1,2000})""",
    """\WRules List:\s{0,100}({alert_type}[^;]{1,2000})""",
    """\WDestination:\s{0,100}(({dest_ip}[A-Fa-f:\d.]{1,2000})|({alert_type}[^;]{1,2000}));""",
    """\WAction:\s{0,100}({outcome}[^;]{1,2000})""",
    """\WCount:\s{0,100}({rule_count}[^;]{1,2000})""",
    """\WRules List:\s{0,100}({alert_name}[^;]{1,2000})""",
    """\WUsers:\s{0,100}(({domain}[^\\\s;]{1,2000})\\+)({user}[^\\\s;]{1,2000})""",
    """\WMAC Address:\s{0,100}({src_mac}[^;,\s]{1,2000})""",
  ]
}
```