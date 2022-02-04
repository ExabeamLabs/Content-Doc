#### Parser Content
```Java
{
Name = checkpoint-network-alert-6
  Vendor = Check Point
  Product = NGFW
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """ CheckPoint """, """action:Detect""", """product=VPN-1 & FireWall-1""", """origin:""" ]
  Fields = [
    """\Wtime:({time}\d{1,100})""",
    """\W({host}[\w\-.]{1,2000}) CheckPoint""",
    """\Wsrc:({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wdst:({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """({outcome}Detect)""",
    """\Ws_port:({src_port}\d{1,100})""",
    """\Wproto:({protocol}[^"]{1,2000})""",
    """\Wservice:({dest_port}\d{1,100})""",
    """\Wseverity:({alert_severity}[^"]{1,2000})""",
    """\Wprotection_name:({protection_name}[^"]{1,2000})""",
    """\Wprotection_type:({alert_type}[^"]{1,2000})""",
    """\Worigin:({origin_ip}[A-Fa-f\d\.:]{1,2000})""",
    """\Worigin_?sic_?name:CN=({origin_name}[^",]{1,2000})""",
    """\Wproduct:({product_name}[^"]{1,2000})""",
    """\Wconfidence_level:({confidence_level}[^"]{1,2000})""",
    """\Wrule_uid:({rule_id}[^"]{1,2000})""",
    """\Wsmartdefense_profile:({smartdefense_profile}[^"]{1,2000})""",
    """ifdir:({direction}[^"]{1,2000})""",
    """originsicname:({user_ou}[^"]{1,2000})""",
    """\Wdescription:({additional_info}[^"]{1,2000})""",
    """\Wpolicy_name=({rule_name}[^"]{1,2000}?)\\\]"""
  ]
  DupFields = ["protection_name->alert_name"]


}
```