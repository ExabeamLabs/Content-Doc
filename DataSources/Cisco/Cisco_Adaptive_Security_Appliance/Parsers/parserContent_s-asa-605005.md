#### Parser Content
```Java
{
Name = s-asa-605005
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Splunk
  DataType = "remote-logon"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "Login permitted from", "-605005", "%ASA-" ]
  Fields = [
    """({time}[a-zA-Z]{3}\s\d{2}\s\d{4}\s\d{2}:\d{2}:\d{2}):\s+""",
    """exabeam_raw=.*?({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """%ASA-({priority}\d+)-({event_code}\d+)""",
    """\w+ \d+ \d+:\d+:\d+ ({host}[\w.\-]+)""",
    """Login permitted from ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """Login permitted from .+? to ({domain}[^:]+)""",
    """Login permitted from .+?:({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """Login permitted from .+? to .+?/({auth}.+?) for user""",
    """user "+({user}[^"]+)"""
  ]
}
```