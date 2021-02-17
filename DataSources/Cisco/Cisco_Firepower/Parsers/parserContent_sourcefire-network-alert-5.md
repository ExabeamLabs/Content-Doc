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
    """<\d+>\w+ \d+ \d+:\d+:\d+ ({host}[\w.\-]+)""",
    """({alert_type}PSECURE_VIOLATION):\s*({alert_name}[^,]+?),""",
    """caused by MAC address ({src_mac}[a-fA-F\d.:]+) on port ({src_interface}[^\.]+)"""
  ]
}
```