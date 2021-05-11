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
    """exabeam_host=({host}[\w\-.]+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[^\s]+)\s{1,20}:\s{1,20}%FTD-""",
    """User\s({user}[^,]+)""",
    """Addr\s({src_ip}\d{1,100}.\d{1,100}.\d{1,100}.\d{1,100})""",
  ]
}
```