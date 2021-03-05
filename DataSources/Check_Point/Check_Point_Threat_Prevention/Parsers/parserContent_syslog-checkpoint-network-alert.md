#### Parser Content
```Java
{
Name = syslog-checkpoint-network-alert
  Vendor = Check Point
  Product = Check Point Threat Prevention
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "ddMMMyyyy HH:mm:ss"
  Conditions = [ """product: SmartDefense;""", """ monitor """ ]
  Fields = [
    """\s({time}\d{2}\w{3}\d{4} \d\d:\d\d:\d\d)\s+\S+\s+\S+\s+product: SmartDefense;""",
    """\s({host}[\w\-\.]+)\s+product: SmartDefense;""",
    """\Wsrc:\s*({src_ip}[\da-fA-F\.:]+);""",
    """\Ws_port:\s*({src_port}\d+);""",
    """\Wdst:\s*({dest_ip}[\da-fA-F\.:]+);""",
    """\Wservice:\s*({dest_port}\d+);""",
    """\Wproto:\s*(|({protocol}.+?));""",
    """\WSeverity:\s*(|({alert_severity}.+?));""",
    """\WProtection Name:\s*(|({alert_name}.+?));""",
    """\WAttack Info:\s*(|({alert_type}.+?));""",
    """\WProtection Type:\s*(|({additional_info}.+?));""",
  ]
  #DupFields = [ "protocol->alert_name", "protocol->alert_type"]
}
```