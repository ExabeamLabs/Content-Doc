#### Parser Content
```Java
{
Name = sourcefire-network-alert-5
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """PORT_SECURITY""", """PSECURE_VIOLATION: Security violation occurred""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\w+\s\d\d\s\d\d:\d\d:\d\d\s(::ffff:)?({host}[a-fA-F\d.:]{1,2000}|[\w.\-]{1,2000})\s{0,100}\d{1,100}:""",
    """<\d{1,100}>\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} ({host}[\w.\-]{1,2000})""",
    """({alert_type}PSECURE_VIOLATION):\s{0,100}({alert_name}[^,]{1,2000}?),""",
    """caused by MAC address ({src_mac}[a-fA-F\d.:]{1,2000}) on port ({src_interface}[^\.]{1,2000})"""
  ]


}
```