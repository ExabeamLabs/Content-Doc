#### Parser Content
```Java
{
Name = pan-config-change
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = QRadar
  DataType = "config-change"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ ",CONFIG," ]
  Fields = [
    """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
    """\d\d:\d\d:\d\d\s(?:-|({host}[^:\s]+))\s\d+,\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d,""",
    """CONFIG,.+?({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """,({host_id}\d+),CONFIG,""",
    """({log_type}CONFIG)""",
    """,CONFIG.+?\s\d\d:\d\d:\d\d,(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^,]+)),""",
    """CONFIG,([^,]*,){5}({activity}[^,]+),""",
    """CONFIG,([^,]*,){6}({user}[^,]+),""",
    """CONFIG,([^,]*,){8}({outcome}[^,]+),""",
    """CONFIG,([^,]*,){9}\s*({object}[^,]+),""",
    """CONFIG,([^,]*,){17}({host}[^\s,]+)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```