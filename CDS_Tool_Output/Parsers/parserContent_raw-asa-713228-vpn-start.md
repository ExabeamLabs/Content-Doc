#### Parser Content
```Java
{
Name = raw-asa-713228-vpn-start
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "Assigned private IP address", "-713228","""%ASA-""" ]
  Fields = [
    """exabeam_time=\s*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({time}\w+ \d+ (\d\d\d\d )?\d+:\d+:\d+):""",
    """exabeam_source=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """exabeam_host=(.+?@\s*)?({host}[\w.\-:]+)""",
    """%ASA-({priority}\d+)-({event_code}\d+): Group =\s*({realm}[^,]+),\s*Username = ({user}[^,@]+?),?\s+IP = ({src_ip}[^\s,]+)[,\s]+Assigned private IP address ({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) to"""
  ]
}
```