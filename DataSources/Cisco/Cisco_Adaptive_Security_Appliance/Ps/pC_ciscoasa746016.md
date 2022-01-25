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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """({host}[\w\-.]{1,2000})\s{1,100}({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d):\s{0,100}%ASA-({priority}\d{1,100})""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\+|\-)\d\d:\d\d)\s{1,100}({host}\S+)\s{1,100}:\s{0,100}%ASA-({priority}\d{1,100})""",
    """({event_code}746016)""",
    """({event_name}DNS lookup) for ({query}\S+)""",
    """,\s{0,100}reason\s{0,100}:\s{0,100}(UNKNOWN|({reason}.+?))\s{0,100}$"""
  ]


}
```