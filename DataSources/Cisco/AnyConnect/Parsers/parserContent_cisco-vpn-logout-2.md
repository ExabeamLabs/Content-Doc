#### Parser Content
```Java
{
Name = cisco-vpn-logout-2
  Vendor = Cisco
  Product = AnyConnect
  Lms = Splunk
  DataType = "vpn-end"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """AnyConnect session lost connection. Waiting to resume."""]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]+)""",
    """({host}[^\s]+)\s{1,20}:\s{1,20}%FTD-""",
    """User\s<({user}[^>]+)""",
    """IP\s<({src_ip}\d{1,100}.\d{1,100}.\d{1,100}.\d{1,100})""",
  ]
}
```