#### Parser Content
```Java
{
Name = raw-asa-svc-vpn-end
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "vpn-end"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "Session disconnected." , "-113019" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({time}\w+ \d+ \d\d\d\d \d+:\d+:\d+)""",
    """exabeam_host=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """exabeam_source=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """exabeam_host=(.+?@\s*)?({host}[\w.\-]+)""",
    """[\s\t]+\d\d:\d\d:\d\d\s+({host}[\w.\-]+).+?%ASA""",
    """({host}[^\s]+)\s{1,20}:\s{1,20}%FTD-""",
    """Username[\s\t]+=[\s\t]+(.+?\\)?(?![^\s]+@[^\s]+)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({user}[^,]+)).+?IP[\s\t]+=[\s\t]+({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """Username[\s\t]+=[\s\t]+(.+?\\)?({user_email}[^,@]+@[^,@]+).+?IP[\s\t]+=[\s\t]+({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sBytes xmt:\s*({bytes_out}\d+)""",
    """\sBytes rcv:\s*({bytes_in}\d+)""",
    """\sDuration:\s*(({session_day}\d+)d )?({session_hour}\d+)h:({session_min}\d+)m:({session_sec}\d+)s""",
    """%ASA-({priority}\d+)-({event_code}\d+)""",
    ]
}
```