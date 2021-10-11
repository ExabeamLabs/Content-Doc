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
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
    """\d\d:\d\d:\d\d\s(?:-|({host}[^:\s]{1,2000}))\s\d{1,100},\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d,""",
    """CONFIG,.+?({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """,({host_id}\d{1,100}),CONFIG,""",
    """({log_type}CONFIG)""",
    """,CONFIG.+?\s\d\d:\d\d:\d\d,(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^,]{1,2000})),""",
    """CONFIG,([^,]{0,2000},){5}({activity}[^,]{1,2000}),""",
    """CONFIG,([^,]{0,2000},){6}({user}[^,]{1,2000}),""",
    """CONFIG,([^,]{0,2000},){8}({outcome}[^,]{1,2000}),""",
    """CONFIG,([^,]{0,2000},){9}\s{0,100}({object}[^,]{1,2000}),""",
    """CONFIG,([^,]{0,2000},){17}({host}[^\s,]{1,2000})"""
  ]
  DupFields = [ "host->dest_host" ]
}
```