#### Parser Content
```Java
{
Name = ncp-vpn-end
  Vendor = NCP
  Product = NCP
  Lms = Direct
  DataType = "vpn-end"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ " disconnect ", """ : incoming : """, "ConTime=" ]
  Fields = [
    """<.+?>\w+ \d+ \d\d:\d\d:\d\d ({host}\S+)\s+disconnect""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """incoming\s*:\s*({user}[^\s@]+)(@({domain}[^\s@]+)\s*:)"""
  ]
}
```