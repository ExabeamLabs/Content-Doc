#### Parser Content
```Java
{
Name = cisco-asa-connection-teardown
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "network-connection-stop"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "%ASA-", "-30201", """: Teardown """, """ duration """ ]
  Fields = [
    """({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d+)""",
    """exabeam_host=(::ffff:)?({host}[^\s]+)""",
    """(\w{3} (\d\d| \d) \d\d\d\d (\d\d| \d):\d\d:\d\d)\s+(::ffff:)?({host}[\w\.-]+)\s*:\s*%ASA-""",
    """%ASA-({priority}\d+)-({event_code}\d+)""",
    """({event_name}Teardown ({protocol}\w+) connection)""",
    """\sconnection\s+({connection_id}\d+)""",
    """\sfor\s+({src_interface}.+?):((::ffff:)?({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|(::ffff:)?({src_host}[^\s]+?))\/({src_port}\d+)""",
    """\sto\s+({dest_interface}.+?):((::ffff:)?({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|(::ffff:)?({dest_host}[^\s]+?))\/({dest_port}\d+)""",
    """\sduration\s+({duration}\S+)\s+bytes\s+({bytes}\d+)(\s+({reason}[^\(]+[^\(\s]))?(\s+\(({user}.+?)\))?""",
    """%ASA-.*?\((({domain}[^\\\/]+)[\\\/]+)?({user}[^\\\/]+?)\)"""
  ]
  DupFields = [ "event_name->activity" ]
}
```