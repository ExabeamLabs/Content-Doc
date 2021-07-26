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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """User\s<({user}[^>]{1,2000})""",
    """IP\s<({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
  ]
}
```