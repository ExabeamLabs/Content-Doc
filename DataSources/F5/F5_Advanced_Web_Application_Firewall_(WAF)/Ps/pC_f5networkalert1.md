#### Parser Content
```Java
{
Name = f5-network-alert-1
  Vendor = F5
  Product = F5 Advanced Web Application Firewall (WAF)
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ perl[""", """] Request """, """ violations: """, """HTTP protocol compliance sub violations:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\w+ \d{1,100} \d\d:\d\d:\d\d ({host}[\w\-.]{1,2000})""",
    """\Wsource ip:\s{0,100}({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wsource port:\s{0,100}({src_port}\d{1,100})""",
    """\Wdestination ip:\s{0,100}({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wdestination port:\s{0,100}({dest_port}\d{1,100})""",
    """] Request ({outcome}[^:,]{1,2000})""",
    """violations:\s{0,100}({alert_name}.+?)\s{0,100}HTTP protocol compliance sub violations:""",
    """\Wrequest:\s{0,100}<\S+ ({additional_info}\S+)""",
    """\Wviolation_rate:\s{0,100}({alert_severity}\d{1,100})""",
    """username:\s{0,100}<(N\/A|({user}[^\s,>]{1,2000}))""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```