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
    """({host}[\w\-\.]+)\s{0,100}:\s{0,100}\S+\s{0,100}\-\s{0,100}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d).*?: Session ended for user""",
    """({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[\w\-\.]+)\s{0,100}(Juniper|PulseSecure):""",
    """PulseSecure:\s{0,100}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s{1,100}\-\s{1,100}({host}[\w\-.]+)""",
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]+)""",
    """\s{1,100}({host}[\w-.]+)\s{1,100}PulseSecure:""",
    """\suser=(({domain}[^\\]+)\\)?({user}[^\s]+)\s""",
    """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """with IP(?:v4 address)?\s{1,100}({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssent=({bytes_out}[^\s]+)""",
    """\srcvd=({bytes_in}[^\s]+)""",
    """PulseSecure:\s{0,100}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\s{1,100}\-\s{1,100}({dest_host}[\w\-.]+)""",
    """\s(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w.\-]+))\s{1,100}(Juniper|PulseSecure):""",
    """\- \[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]"""
    """\- \[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\s{1,100}(\w+\\)?([\w\s]+?::)?({user}[^\(]+)\([^\[]+\)\[(?!Machine Cert)""",
    """duration=({session_duration}[^\s]+)\s{1,100}"""
  ]
  DupFields = [ "host->dest_host" ]
}
```