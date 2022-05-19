#### Parser Content
```Java
{
Name = raw-juniper-nwc-vpn-connected
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """: User with IP """, """ connected with """, """VPN Tunneling:""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\s-\s""",
    """\stime="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\sfw=(::ffff:)?({host}[\w\-\.]{1,2000})""",
    """(::ffff:)?({host}[\w\-\.]{1,2000})\s{1,100}(Juniper|PulseSecure):""",
    """PulseSecure:\s{0,100}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s{1,100}\-\s{1,100}(::ffff:)?({host}[\w\-.]{1,2000})""",
    """exabeam_host=(.+?@\s{0,100})?(::ffff:)?(gcs-topic|({host}[^\s]{1,2000}))""",
    """\s{1,20}(::ffff:)?({host}[\w\-.]{1,2000})\s{1,20}PulseSecure:""",
    """PulseSecure:\s{0,100}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\s{1,100}\-\s{1,100}({dest_host}[\w\-.]{1,2000})""",
    """\s(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-\.]{1,2000}))\s{1,100}(Juniper|PulseSecure):""",
    """\- \[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\s{1,100}(({domain}[^\\]{1,2000})\\)?({user}[^\(]{1,2000})\(({realm}[^\)]{1,2000})?\)""",
    """user=({user}[^\s]{1,2000})""",
    """: User with IP ({src_translated_ip}[A-Fa-f\d:.]{1,2000})""",
    """src=({src_ip}[A-Fa-f\d:.]{1,2000})"""
  ]
  DupFields = [ "host->dest_host" , "user->account"]


}
```