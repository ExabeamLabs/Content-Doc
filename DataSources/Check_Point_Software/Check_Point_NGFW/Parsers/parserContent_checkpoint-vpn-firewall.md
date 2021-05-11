#### Parser Content
```Java
{
Name = checkpoint-vpn-firewall
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  DataType = "network-connection"
  Conditions = [ """ProductName="VPN-1 & FireWall-1""", """ProductFamily="Network"""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\S+\s({host}\d{1,100}.\d{1,100}.\d{1,100}.\d{1,100})\s""",
    """src="({src_ip}\d{1,100}.\d{1,100}.\d{1,100}.\d{1,100})""",
    """dst="({dest_ip}\d{1,100}.\d{1,100}.\d{1,100}.\d{1,100})""",
    """proto="({protocol}[^"]+)""",
    """sport_svc="({src_port}[^"]+)""",
    """svc="({dest_port}[^"]+)""",
    """xlatedst="({dest_translated_ip}\d{1,100}.\d{1,100}.\d{1,100}.\d{1,100})""",
    """rule_name="(?:({rule}[^"]+))"""",
    """vpn_feature_name="{1,20}({vpn_feature_name}[^"]+)"""",
    """vpn_user="{1,20}({user}[^"]+)"""",
    """inzone="{1,20}({inzone}[^"]+)"""",
    """outzone="{1,20}({outzone}[^"]+)"""",
    """service_id="{1,20}({service_id}[^"]+)"""",
    """community="{1,20}(|({community}[^"]+))"{1,20}\s(\w+=|$)""",
  ]
}
```