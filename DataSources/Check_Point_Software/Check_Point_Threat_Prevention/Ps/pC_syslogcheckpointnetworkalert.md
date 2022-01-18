#### Parser Content
```Java
{
Name = syslog-checkpoint-network-alert
  Vendor = Check Point Software
  Product = Check Point Threat Prevention
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "ddMMMyyyy HH:mm:ss"
  Conditions = [ """product: SmartDefense;""", """ monitor """ ]
  Fields = [
    """\s({time}\d{2}\w{3}\d{4} \d\d:\d\d:\d\d)\s{1,100}\S+\s{1,100}\S+\s{1,100}product: SmartDefense;""",
    """\s({host}[\w\-\.]{1,2000})\s{1,100}product: SmartDefense;""",
    """\Wsrc:\s{0,100}({src_ip}[\da-fA-F\.:]{1,2000});""",
    """\Ws_port:\s{0,100}({src_port}\d{1,100});""",
    """\Wdst:\s{0,100}({dest_ip}[\da-fA-F\.:]{1,2000});""",
    """\Wservice:\s{0,100}({dest_port}\d{1,100});""",
    """\Wproto:\s{0,100}(|({protocol}.+?));""",
    """\WSeverity:\s{0,100}(|({alert_severity}.+?));""",
    """\WProtection Name:\s{0,100}(|({alert_name}.+?));""",
    """\WAttack Info:\s{0,100}(|({alert_type}.+?));""",
    """\WProtection Type:\s{0,100}(|({additional_info}.+?));""",
  ]
  #DupFields = [ "protocol->alert_name", "protocol->alert_type"]


}
```