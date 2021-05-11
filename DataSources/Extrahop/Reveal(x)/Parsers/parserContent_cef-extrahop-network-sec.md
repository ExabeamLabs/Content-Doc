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
    """\Wrt=({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100}Z)""",
    """({host}[\w.-]+)\s{1,100}CEF:""",
    """cs1=({additional_info}[^=]+)\s\w+=""",
    """cs2=({event_name}[^=]+)\s\w+=""",
    """CEF:\d{1,100}\|([^\|]+\|){4}({alert_name}[^\|]+)""",
    """cn1=({alert_id}\d{1,100})""",
    """cn2=({risk_score}\d{1,100})""",
    """dst=({dest_ip}[A-Fa-f.:\d]+)""",
    """CEF:\d{1,100}\|([^\|]+\|){3}({alert_severity}\d{1,100})""",
]
  DupFields = ["alert_name->alert_type"]
}
```