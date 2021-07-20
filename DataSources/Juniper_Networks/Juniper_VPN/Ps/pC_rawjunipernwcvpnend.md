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
    """\sfw=({host}[\w\-\.]{1,2000})""",
    """({host}[\w\-\.]{1,2000})\s{0,100}:\s{0,100}\S+\s{0,100}\-\s{0,100}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d).*?: Session ended for user""",
    """({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[\w\-\.]{1,2000})\s{0,100}(Juniper|PulseSecure):""",
    """PulseSecure:\s{0,100}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s{1,100}\-\s{1,100}({host}[\w\-.]{1,2000})""",
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
    """\s{1,100}({host}[\w-.]{1,2000})\s{1,100}PulseSecure:""",
    """\suser=(({domain}[^\\]{1,2000})\\)?({user}[^\s]{1,2000})\s""",
    """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """with IP(?:v4 address)?\s{1,100}({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssent=({bytes_out}[^\s]{1,2000})""",
    """\srcvd=({bytes_in}[^\s]{1,2000})""",
    """PulseSecure:\s{0,100}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\s{1,100}\-\s{1,100}({dest_host}[\w\-.]{1,2000})""",
    """\s(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w.\-]{1,2000}))\s{1,100}(Juniper|PulseSecure):""",
    """\- \[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]"""
    """\- \[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\s{1,100}(\w+\\)?([\w\s]{1,2000}?::)?({user}[^\(]{1,2000})\([^\[]{1,2000}\)\[(?!Machine Cert)""",
    """duration=({session_duration}[^\s]{1,2000})\s{1,100}"""
  ]
  DupFields = [ "host->dest_host" ]
}
```