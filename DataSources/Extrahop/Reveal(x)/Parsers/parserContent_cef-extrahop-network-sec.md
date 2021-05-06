#### Parser Content
```Java
{
Name = cef-extrahop-network-sec
  Vendor = Extrahop
  Product = Reveal(x)
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """ExtraHop|Reveal(x)""", """cn2Label=riskScore""", """cs2Label=category""" ]
  Fields = [
    """\Wrt=({time}\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)""",
    """({host}[\w.-]+)\s+CEF:""",
    """cs1=({additional_info}[^=]+)\s\w+=""",
    """cs2=({event_name}[^=]+)\s\w+=""",
    """CEF:\d+\|([^\|]+\|){4}({alert_name}[^\|]+)""",
    """cn1=({alert_id}\d+)""",
    """cn2=({risk_score}\d+)""",
    """dst=({dest_ip}[A-Fa-f.:\d]+)""",
    """CEF:\d+\|([^\|]+\|){3}({alert_severity}\d+)""",
]
  DupFields = ["alert_name->alert_type"]
}
```