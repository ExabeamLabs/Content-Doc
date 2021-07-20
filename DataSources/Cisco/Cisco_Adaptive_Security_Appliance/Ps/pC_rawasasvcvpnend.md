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
    """({time}\w+ \d{1,100} \d\d\d\d \d{1,100}:\d{1,100}:\d{1,100})""",
    """exabeam_host=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """exabeam_source=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """exabeam_host=(.+?@\s{0,100})?({host}[\w.\-]{1,2000})""",
    """[\s\t]{1,2000}\d\d:\d\d:\d\d\s{1,100}({host}[\w.\-]{1,2000}).+?%ASA""",
    """({host}[^\s]{1,2000})\s{1,20}:\s{1,20}%FTD-""",
    """Username[\s\t]{1,2000}=[\s\t]{1,2000}(.+?\\)?(?![^\s]{1,2000}@[^\s]{1,2000})(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({user}[^,]{1,2000})).+?IP[\s\t]{1,2000}=[\s\t]{1,2000}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """Username[\s\t]{1,2000}=[\s\t]{1,2000}(.+?\\)?({user_email}[^,@]{1,2000}@[^,@]{1,2000}).+?IP[\s\t]{1,2000}=[\s\t]{1,2000}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sBytes xmt:\s{0,100}({bytes_out}\d{1,100})""",
    """\sBytes rcv:\s{0,100}({bytes_in}\d{1,100})""",
    """\sDuration:\s{0,100}(({session_day}\d{1,100})d )?({session_hour}\d{1,100})h:({session_min}\d{1,100})m:({session_sec}\d{1,100})s""",
    """%ASA-({priority}\d{1,100})-({event_code}\d{1,100})""",
    ]
}
```