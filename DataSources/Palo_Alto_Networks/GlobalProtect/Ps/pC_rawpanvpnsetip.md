#### Parser Content
```Java
{
Name = raw-pan-vpn-set-ip
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Splunk
  DataType = "vpn-set-ip"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,globalprotect,""", "client configuration generated" ]
  Fields = [
    """({time}\d\d\d\d/\d\d/\d\d \d{1,100}:\d{1,100}:\d{1,100})""",
    """globalprotect(gateway|portal)-\S+?,({host}[^,]{1,2000}),""",
    """:\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})""",
    """SYSTEM,([^,]{0,2000}
```