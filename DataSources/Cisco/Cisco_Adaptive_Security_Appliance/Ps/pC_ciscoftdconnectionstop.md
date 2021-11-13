#### Parser Content
```Java
{
Name = cisco-ftd-connection-stop
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "network-connection-stop"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "%FTD-", "-30202", "Teardown ", " connection " ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w\-.]{1,2000})\s{0,100}:\s{0,100}%FTD-""",
    """%FTD-({priority}\d{1,100})-({event_code}\d{1,100})""",
    """({event_name}Teardown ({protocol}\w+) connection)""",
    """\sfaddr\s{1,100}((({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|({dest_host}[^\s]{1,2000}?))((\/({dest_port}\d{1,100}))|(\s|$))|({icmp_seq_num}\S+))""",
    """\sgaddr\s{1,100}((({dest_translated_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|({dest_translated_host}[^\s]{1,2000}?))((\/({dest_translated_port}\d{1,100}))|(\s|$))|({icmp_type}\S+))""",
    """\sladdr\s{1,100}(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|({src_host}[^\s]{1,2000}?))((\/({src_port}\d{1,100}))|(\s|$))""",
    """for\s{1,100}[^\s:]{1,2000}:\s{0,100}((({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|({src_host}[^\s]{1,2000}?))((\/({src_port}\d{1,100}))|(\s|$))|({icmp_type}\S+))""",
    """to\s{1,100}[^\s:]{1,2000}:\s{0,100}(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|({dest_host}[^\s]{1,2000}?))((\/({dest_port}\d{1,100}))|(\s|$))""", 
    """\sbytes\s{1,100}({bytes}\d{1,100})""",
    """%FTD-.*?\((({domain}[^\\\/]{1,2000})[\\\/]{1,2000})?(?:({user_email}[^@\\\/]{1,2000}@[^@\\\/]{1,2000}?)|({user}[^\\\/]{1,2000}?))\)"""
  ]
  DupFields = [ "event_name->activity" ]


}
```