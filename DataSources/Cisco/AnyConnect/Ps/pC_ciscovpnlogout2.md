#### Parser Content
```Java
{
Name = cisco-vpn-logout-2
  Vendor = Cisco
  Product = AnyConnect
  Lms = Splunk
  DataType = "vpn-end"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """AnyConnect session lost connection. Waiting to resume."""]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """\w{1,3}\s{1,2}\d{1,2}\s\d\d:\d\d:\d\d\s({host}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w.\-]{1,2000}))\s%ASA-""",
    """({host}[^\s]{1,2000})\s{1,20}:\s{1,20}%FTD-""",
    """User\s{1,100}<(({user_email}[^@>]{1,2000}@[^>]{1,2000})|({user}[^>]{1,2000}))>""",
    """IP\s<({src_ip}\d{1,100}.\d{1,100}.\d{1,100}.\d{1,100})""",
  ]


}
```