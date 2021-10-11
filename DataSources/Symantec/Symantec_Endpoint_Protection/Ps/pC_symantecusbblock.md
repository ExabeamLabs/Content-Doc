#### Parser Content
```Java
{
Name = symantec-usb-block
    Vendor = Symantec
    Product = Symantec Endpoint Protection
    Lms = Splunk
    DataType = "usb-insert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """,Blocked,""", """,Begin:""", """,Action Type:""", """,Device ID:""" ]
    Fields = [ """exabeam_host=({host}[^,\s]{1,2000})""",
      """SymantecServer:\s{0,100}({host}[\w\-.]{1,2000})""",
      """(0.0.0.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^\s,]{1,2000})),Blocked,""",
      """Begin:\s{1,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """Rule: [^,]{0,2000},\d{1,100},({target}[^,]{1,2000}),\d{1,100},[^,]{0,2000},"?({file_name}.+?)"?,User""",
      """Rule: [^,]{0,2000},\d{1,100},({process}.*(\/|\\)({process_name}[^\/\\]{1,2000})),\d,""",
      """\| \[[^,]{0,2000},\d{1,100},[^,]{1,2000},\d{1,100},[^,]{1,2000},.*/({file_name}.+?)"?,User""",
      """User:\s{1,100}(SYSTEM|({user}[^\s]{1,2000}?)),Domain""",
      """User Name:\s{0,100}(SYSTEM|({user}[^\s,]{1,2000}))""",
      """Domain:\s{1,100}({domain}.+?),Action Type""",
      """File size \(({bytes_unit}.+?)\):\s{0,100}({bytes_num}\d{1,100})""",
      """Device ID:\s{1,100}({device_id}.+)&\d{1,100}""",
      """({outcome}Blocked)""",
      """File size \(({bytes_unit}[^\)]{1,2000})""",
      """({activity}Blocked)"""
    ]
  }
```