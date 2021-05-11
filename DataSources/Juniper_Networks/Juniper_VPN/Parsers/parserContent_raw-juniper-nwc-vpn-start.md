#### Parser Content
```Java
{
Name = raw-juniper-nwc-vpn-start
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ ": Session started for user" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\s-\s""",
    """\stime="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""",
    """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """\sfw=({host}[\w\-\.]+)""",
    """({host}[\w\-\.]+)\s{0,100}:\s{0,100}\S+\s{0,100}\-\s{0,100}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d).*?: Session started for user""",
    """({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[\w\-\.]+)\s{0,100}(Juniper|PulseSecure):""",
    """PulseSecure:\s{0,100}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s{1,100}\-\s{1,100}({host}[\w\-.]+)""",
    """exabeam_host=([^=]+?@\s{0,100})?({host}[^\s]+)""",
    """\s{1,100}({host}[\w-.]+)\s{1,100}PulseSecure:""",
    """PulseSecure:\s{0,100}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\s{1,100}\-\s{1,100}({dest_host}[\w\-.]+)""",
    """,\s{1,100}hostname\s{1,100}({src_host}[\w.\-]+)""",
    """\s(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w.\-]+))\s{1,100}(Juniper|PulseSecure):""",
    """\- \[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]"""
    """\- \[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\s{1,100}([\w\s]+?::)?(({domain}[^\\]+)\\)?({user}[^\(]+)\(({realm}[^\[]+)?\)\[(?!Machine Cert)""",
    """\suser=(({domain}[^\\=]+)\\)?({user}.+?)\s{1,100}\w+=""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s""",
    """with IP(?:v4 address)?\s{1,100}({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\srealm=[\\"]*({realm}.+?)[\\"]*(\s{1,100}\w+=|\s{0,100}")""",
    """\sroles=[\\"]*({roles}.+?)[\\"]*(\s{1,100}\w+=|\s{0,100}")""",
    """\svpn=[\\"]*({vpn}.+?)[\\"]*(\s{1,100}\w+=|\s{0,100}")""",
  ]
  DupFields = [ "host->dest_host" , "user->account"]
}
```