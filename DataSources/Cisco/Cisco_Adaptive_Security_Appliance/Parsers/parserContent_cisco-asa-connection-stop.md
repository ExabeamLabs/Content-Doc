#### Parser Content
```Java
{
Name = cisco-asa-connection-stop
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "network-connection-stop"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "%ASA-", "-30202", "Teardown ", " connection " ]
  Fields = [
    """({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d{1,100})""",
    """(\w{3} (\d\d| \d) \d\d\d\d (\d\d| \d):\d\d:\d\d)\s{1,100}(::ffff:)?({host}[\w\.-]+)\s{0,100}:\s{0,100}%ASA-""",
    """%ASA-({priority}\d{1,100})-({event_code}\d{1,100})""",
    """({event_name}Teardown ({protocol}\w+) connection)""",
    """\sfaddr\s{1,100}(((::ffff:)?({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|(::ffff:)?({dest_host}[^\s]+?))((\/({dest_port}\d{1,100}))|(\s|$))|({icmp_seq_num}\S+))""",
    """\sgaddr\s{1,100}(((::ffff:)?({dest_translated_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|(::ffff:)?({dest_translated_host}[^\s]+?))((\/({dest_translated_port}\d{1,100}))|(\s|$))|({icmp_type}\S+))""",
    """\sladdr\s{1,100}((::ffff:)?({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|(::ffff:)?({src_host}[^\s]+?))((\/({src_port}\d{1,100}))|(\s|$))""",
    """for\s{1,100}[^\s:]+:\s{0,100}(((::ffff:)?({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|(::ffff:)?({src_host}[^\s]+?))((\/({src_port}\d{1,100}))|(\s|$))|({icmp_type}\S+))""",
    """to\s{1,100}[^\s:]+:\s{0,100}((::ffff:)?({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|(::ffff:)?({dest_host}[^\s]+?))((\/({dest_port}\d{1,100}))|(\s|$))""", 
    """\sbytes\s{1,100}({bytes}\d{1,100})""",
    """%ASA-.*?\((({domain}[^\\\/]+)[\\\/]+)?(?:({user_email}[^@\\\/]+@[^@\\\/]+?)|({user}[^\\\/]+?))\)"""
  ]
  DupFields = [ "event_name->activity" ]
}
```