#### Parser Content
```Java
{
Name = ncp-vpn-start
  Vendor = NCP
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ " connect ", """ : incoming : """, "IP=" ]
  Fields = [
    """<.+?>\w+ \d+ \d\d:\d\d:\d\d ({host}\S+)\s+connect""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """incoming\s*:\s*({user}[^\s@]+)(@({domain}[^\s@]+)\s*:)""",
    """IP=({src_ip}[a-fA-F\d.:]+)""",
    """VpnEp=({dest_ip}[a-fA-F\d.:]+)""",
    """Group=({realm}\w+)"""
  ]
  DupFields = ["user->account"]
}
```