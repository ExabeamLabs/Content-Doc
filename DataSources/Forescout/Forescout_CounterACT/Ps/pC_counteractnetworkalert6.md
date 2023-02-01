#### Parser Content
```Java
{
Name = counteract-network-alert-6
  Vendor = Forescout
  Product = Forescout CounterACT
  Lms = Splunk
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Block Event:""", """Target:""", """rule: true""", """Reason:""", """Virtual Firewall - Limit Inbound""", """Is Virtual Firewall blocking""" ]
  Fields = [
    """\d\d:\d\d:\d\d\s({host}[\w\-.]{1,2000})""",
    """({alert_name}Block Event)""",
    """Host:\s{0,100}({dest_ip}[A-Fa-f\d:.]{1,2000})""",
    """Target:\s{0,100}(({dest_ip}[A-Fa-f\d:.]{1,2000})|({dest_host}[^\s]{1,2000}))""",
    """Service:\s{0,100}({dest_port}\d{1,5})""",
    """({activity}Virtual Firewall blocking)""",
    """Reason:\s{0,100}({failure_reason}Virtual Firewall - Limit Inbound)""",
  ]


}
```