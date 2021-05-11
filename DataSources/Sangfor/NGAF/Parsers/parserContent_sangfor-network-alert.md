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
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}[\+\-]\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]+)""",
    """, policy name:\s{0,100}({policy}[^,]+)""",
    """, vulnerability ID:\s{0,100}({alert_id}[^,]+)""",
    """, vulnerability name:\s{0,100}({alert_name}[^,]+)""",
    """, Src IP:\s{0,100}({src_ip}[A-Fa-f:\d.]+)""",
    """, Src port:\s{0,100}({src_port}\d{1,100})""",
    """, dst IP:\s{0,100}({dest_ip}[A-Fa-f:\d.]+)""",
    """, Dst port:\s{0,100}({dest_port}\d{1,100})""",
    """, protocol:\s{0,100}({protocol}[^,]+)""",
    """, attack type:\s{0,100}({alert_type}[^,]+)""",
    """, threat level:\s{0,100}({alert_severity}[^,]+)""",
    """, action:\s{0,100}({outcome}[^,\s]+)""",
  ]
}
```