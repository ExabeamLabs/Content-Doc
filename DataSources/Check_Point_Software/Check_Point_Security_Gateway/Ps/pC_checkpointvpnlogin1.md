#### Parser Content
```Java
{
Name = checkpoint-vpn-login-1
  Vendor = Check Point Software
  Product = Check Point Security Gateway
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "ddMMMyyyy-HH:mm:ss"
  Conditions = [ """product=VPN-1 & FireWall-1""", """['vpn_feature_name': """, """['origin_sic_name': """ ]
  Fields = [
    """Time:\s{0,100}({time}\d\d\w+\d\d\d\d-\d\d:\d\d:\d\d)""",
    """'user':\s{0,100}"({user}[^"]{1,2000})""",
    """'origin_sic_name':\s{0,100}"(CN=)?({host}[^",]{1,2000})""",
    """Direction:\s{0,100}({direction}\w+)\s{1,100}Connection""",
    """Action:\s{0,100}(|({action}.+?))\s{0,100}OriginSicName:""",
    """'src':\s{0,100}({src_ip}[a-fA-F\d.:]{1,2000})""",
    """'dst':\s{0,100}({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """'s_port':\s{0,100}({src_port}\d{1,100})""",
    """'service':\s{0,100}({dest_port}\d{1,100})""",
  ]


}
```