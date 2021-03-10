#### Parser Content
```Java
{
Name = checkpoint-vpn-firewall
  Vendor = Check Point
  Product = Check Point NGFW
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  DataType = "network-connection"
  Conditions = [ """ProductName="VPN-1 & FireWall-1""", """ProductFamily="Network"""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)--\d+:\d\d\s({host}\d+.\d+.\d+.\d+)""",
    """src="({src_ip}\d+.\d+.\d+.\d+)""",
    """dst="({dest_ip}\d+.\d+.\d+.\d+)""",
    """proto="({protocol}[^"]+)""",
    """sport_svc="({src_port}[^"]+)""",
    """svc="({dest_port}[^"]+)""",
    """xlatedst="({dest_translated_ip}\d+.\d+.\d+.\d+)""",
    """rule_name="({rule}[^"]+)""",
  ]
}
```