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
    """({host}[\w\-.]+)\s*:\s*%FTD-""",
    """%FTD-({priority}\d+)-({event_code}\d+)""",
    """({event_name}Teardown ({protocol}\w+) connection)""",
    """\sfaddr\s+((({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|({dest_host}[^\s]+?))((\/({dest_port}\d+))|(\s|$))|({icmp_seq_num}\S+))""",
    """\sgaddr\s+((({dest_translated_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|({dest_translated_host}[^\s]+?))((\/({dest_translated_port}\d+))|(\s|$))|({icmp_type}\S+))""",
    """\sladdr\s+(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|({src_host}[^\s]+?))((\/({src_port}\d+))|(\s|$))""",
    """for\s+[^\s:]+:\s*((({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|({src_host}[^\s]+?))((\/({src_port}\d+))|(\s|$))|({icmp_type}\S+))""",
    """to\s+[^\s:]+:\s*(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|({dest_host}[^\s]+?))((\/({dest_port}\d+))|(\s|$))""", 
    """\sbytes\s+({bytes}\d+)""",
    """%FTD-.*?\((({domain}[^\\\/]+)[\\\/]+)?(?:({user_email}[^@\\\/]+@[^@\\\/]+?)|({user}[^\\\/]+?))\)"""
  ]
  DupFields = [ "event_name->activity" ]
}
```