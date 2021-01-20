#### Parser Content
```Java
{
Name = cisco-vpn-start-3
  Vendor = Cisco
  Product = AnyConnect
  Lms = Splunk
  DataType = "vpn-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Connection AnyConnect: The following DAP records were selected for this connection: DfltAccessPolicy"""]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """User\s({user}[^,]+)""",
    """Addr\s({src_ip}\d+.\d+.\d+.\d+)""",
  ]
}
```