#### Parser Content
```Java
{
Name = raw-juniper-nwc-vpn-end
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = Direct
  DataType = "vpn-end"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ ": Session ended for user" ]
  Fields = [
    """\stime="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)(\s|")""",
    """\sfw=({host}[\w\-\.]+)""",
    """({host}[\w\-\.]+)\s*:\s*\S+\s*\-\s*({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d).*?: Session ended for user""",
    """({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[\w\-\.]+)\s*(Juniper|PulseSecure):""",
    """PulseSecure:\s*({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s+\-\s+({host}[\w\-.]+)""",
    """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
    """\suser=(({domain}[^\\]+)\\)?({user}[^\s]+)\s""",
    """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """with IP(?:v4 address)?\s+({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssent=({bytes_out}[^\s]+)""",
    """\srcvd=({bytes_in}[^\s]+)""",
    """PulseSecure:\s*\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\s+\-\s+({dest_host}[\w\-.]+)""",
    """\s(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w.\-]+))\s+(Juniper|PulseSecure):""",
    """\- \[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]"""
    """\- \[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\s+(\w+\\)?({user}[^\(]+)\([^\[]+\)\[(?!Machine Cert)""",
    """duration=({session_duration}[^\s]+)\s+"""
  ]
  DupFields = [ "host->dest_host" ]
}
```