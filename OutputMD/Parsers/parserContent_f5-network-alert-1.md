#### Parser Content
```Java
{
Name = f5-network-alert-1
  Vendor = F5
  Product = WAF F5
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ perl[""", """] Request """, """ violations: """, """HTTP protocol compliance sub violations:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\w+ \d+ \d\d:\d\d:\d\d ({host}[\w\-.]+)""",
    """\Wsource ip:\s*({src_ip}[A-Fa-f:\d.]+)""",
    """\Wsource port:\s*({src_port}\d+)""",
    """\Wdestination ip:\s*({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wdestination port:\s*({dest_port}\d+)""",
    """] Request ({outcome}[^:,]+)""",
    """violations:\s*({alert_name}.+?)\s*HTTP protocol compliance sub violations:""",
    """\Wrequest:\s*<\S+ ({additional_info}\S+)""",
    """\Wviolation_rate:\s*({alert_severity}\d+)""",
    """username:\s*<(N\/A|({user}[^\s,>]+))""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```