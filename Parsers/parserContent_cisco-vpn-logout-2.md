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
    """User\s<({user}[^>]+)""",
    """IP\s<({src_ip}\d+.\d+.\d+.\d+)""",
  ]
}
```