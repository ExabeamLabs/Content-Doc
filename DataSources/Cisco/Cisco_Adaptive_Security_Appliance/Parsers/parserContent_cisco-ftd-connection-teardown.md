#### Parser Content
```Java
{
Name = cisco-ftd-connection-teardown
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "network-connection-stop"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "%FTD-", "-30201", """: Teardown """, """ duration """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w\-.]+)\s{0,100}:\s{0,100}%FTD-""",
    """%FTD-({priority}\d{1,100})-({event_code}\d{1,100})""",
    """({event_name}Teardown ({protocol}\w+) connection)""",
    """\sconnection\s{1,100}({connection_id}\d{1,100})""",
    """\sfor\s{1,100}({src_interface}.+?):(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|({src_host}[^\s]+?))\/({src_port}\d{1,100})""",
    """\sto\s{1,100}({dest_interface}.+?):(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|({dest_host}[^\s]+?))\/({dest_port}\d{1,100})""",
    """\sduration\s{1,100}({duration}\S+)\s{1,100}bytes\s{1,100}({bytes}\d{1,100})(\s{1,100}({reason}[^\(]+[^\(\s]))?(\s{1,100}\(({user}.+?)\))?""",
    """%FTD-.*?\((({domain}[^\\\/]+)[\\\/]+)?({user}[^\\\/]+?)\)"""
  ]
  DupFields = [ "event_name->activity" ]
}
```