#### Parser Content
```Java
{
Name = cisco-asa-746016
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "dns-response"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "-746016", "%ASA-" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
    """({host}[\w\-.]+)\s+({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d):\s*%ASA-({priority}\d+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\+|\-)\d\d:\d\d)\s+({host}\S+)\s+:\s*%ASA-({priority}\d+)""",
    """({event_code}746016)""",
    """({event_name}DNS lookup) for ({query}\S+)""",
    """,\s*reason\s*:\s*(UNKNOWN|({reason}.+?))\s*$"""
  ]
}
```