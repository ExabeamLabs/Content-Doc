#### Parser Content
```Java
{
Name = symantec-usb-block
    Vendor = Symantec
    Product = Symantec DLP
    Lms = Splunk
    DataType = "usb-insert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ ",Blocked,", ",Begin:", ",Action Type:", ",Device ID:" ]
    Fields = [ """exabeam_host=({host}[^,\s]+)""",
      """SymantecServer:\s*({host}[\w\-.]+)""",
      """(0.0.0.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^\s,]+)),Blocked,""",
      """Begin:\s+({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """Rule: [^,]*,\d+,({target}[^,]+),\d+,[^,]*,"?({file_name}.+?)"?,User""",
      """Rule: [^,]*,\d+,({process}.*(\/|\\)({process_name}[^\/\\]+)),\d,""",
      """\| \[[^,]*,\d+,[^,]+,\d+,[^,]+,.*/({file_name}.+?)"?,User""",
      """User:\s+(SYSTEM|({user}[^\s]+?)),Domain""",
      """User Name:\s*(SYSTEM|({user}[^\s,]+))""",
      """Domain:\s+({domain}.+?),Action Type""",
      """File size \(({bytes_unit}.+?)\):\s*({bytes_num}\d+)""",
      """Device ID:\s+({device_id}.+)&\d+""",
      """({outcome}Blocked)""",
      """File size \(({bytes_unit}[^\)]+)""",
      """({activity}Blocked)"""
    ]
  }
```