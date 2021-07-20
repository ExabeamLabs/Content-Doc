#### Parser Content
```Java
{
Name = sangfor-network-alert
  Vendor = Sangfor
  Product = NGAF
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """type: IPS""", """<Identifier>ZC01_NTTDHK-FWL-002</Identifier>""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}[\+\-]\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]{1,2000})""",
    """, policy name:\s{0,100}({policy}[^,]{1,2000})""",
    """, vulnerability ID:\s{0,100}({alert_id}[^,]{1,2000})""",
    """, vulnerability name:\s{0,100}({alert_name}[^,]{1,2000})""",
    """, Src IP:\s{0,100}({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """, Src port:\s{0,100}({src_port}\d{1,100})""",
    """, dst IP:\s{0,100}({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """, Dst port:\s{0,100}({dest_port}\d{1,100})""",
    """, protocol:\s{0,100}({protocol}[^,]{1,2000})""",
    """, attack type:\s{0,100}({alert_type}[^,]{1,2000})""",
    """, threat level:\s{0,100}({alert_severity}[^,]{1,2000})""",
    """, action:\s{0,100}({outcome}[^,\s]{1,2000})""",
  ]
}
```