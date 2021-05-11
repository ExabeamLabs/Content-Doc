#### Parser Content
```Java
{
Name = ncp-vpn-start
  Vendor = NCP
  Product = NCP
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ " connect ", """ : incoming : """, "IP=" ]
  Fields = [
    """<.+?>\w+ \d{1,100} \d\d:\d\d:\d\d ({host}\S+)\s{1,100}connect""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """incoming\s{0,100}:\s{0,100}({user}[^\s@]+)(@({domain}[^\s@]+)\s{0,100}:)""",
    """IP=({src_ip}[a-fA-F\d.:]+)""",
    """VpnEp=({dest_ip}[a-fA-F\d.:]+)""",
    """Group=({realm}\w+)"""
  ]
  DupFields = ["user->account"]
}
```