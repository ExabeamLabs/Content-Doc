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
    """\w+\s+\d+\s+\d+:\d+:\d+[\+\-]\d+:\d+\s+({host}[\w\-.]+)""",
    """, policy name:\s*({policy}[^,]+)""",
    """, vulnerability ID:\s*({alert_id}[^,]+)""",
    """, vulnerability name:\s*({alert_name}[^,]+)""",
    """, Src IP:\s*({src_ip}[A-Fa-f:\d.]+)""",
    """, Src port:\s*({src_port}\d+)""",
    """, dst IP:\s*({dest_ip}[A-Fa-f:\d.]+)""",
    """, Dst port:\s*({dest_port}\d+)""",
    """, protocol:\s*({protocol}[^,]+)""",
    """, attack type:\s*({alert_type}[^,]+)""",
    """, threat level:\s*({alert_severity}[^,]+)""",
    """, action:\s*({outcome}[^,\s]+)""",
  ]
}
```