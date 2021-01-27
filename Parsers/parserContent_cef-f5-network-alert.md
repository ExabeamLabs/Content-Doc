#### Parser Content
```Java
{
Name = cef-f5-network-alert
  Vendor = F5
  Product = F5 BIG-IP Application Security Manager (ASM)
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """CEF:""","""|F5|Advanced Firewall Module|""","""cs6=Attack""","""cs4Label=dos_mode""","""cs5Label=dos_src"""]
  Fields = [
    """rt=({time}\w+\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d)""",
    """dvchost=({host}[^\s]+)""",
    """dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """dpt=({dest_port}\d+)""",
    """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """spt=({src_port}\d+)""",
    """act=(None|({action}[^\s]+))""",
    """CEF:[^|]+\|([^|]+\|){4}(\/[^|]+|({alert_name}[^|]+))""",
    """CEF:[^|]+\|([^|]+\|){4}({alert_name}\/[^=]+)\/""",
    """CEF:[^|]+\|([^|]+\|){5}({alert_severity}[^|]+)""",
    """cs5=({additional_info}[^=]+?)\s+\w+=""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```