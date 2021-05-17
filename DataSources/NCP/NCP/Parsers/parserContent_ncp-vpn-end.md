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
    """<.+?>\w+ \d{1,100} \d\d:\d\d:\d\d ({host}\S+)\s{1,100}disconnect""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """incoming\s{0,100}:\s{0,100}({user}[^\s@]{1,2000})(@({domain}[^\s@]{1,2000})\s{0,100}:)"""
  ]
}
```