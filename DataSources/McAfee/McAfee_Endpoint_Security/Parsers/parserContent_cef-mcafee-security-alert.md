#### Parser Content
```Java
{
Name = cef-mcafee-security-alert
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = ArcSight
    DataType = "alert"
    TimeFormat = "epoch"
    Conditions = [ """CEF:""", """|McAfee|Host Intrusion Prevention|""" ]
    Fields = [
      """CEF:([^\|]{0,2000}\|){5}({alert_name}[^\|]{1,2000})\|""",
      """CEF:([^\|]{0,2000}\|){6}({alert_severity}[^\|]{1,2000})\|""",
      """\Wcat=({alert_type}.+?)\s{1,100}(\w+=|$)""",
      """\Wrt=({time}\d{1,100})""",
      """\Wshost=({src_host}.+?)\s{1,100}(\w+=|$)""",
      """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
      """\Wsuser=(?!NT AUTHORITY)(({domain}[^\\\/=]{1,2000}?)[\\\/]{1,2000})?({user}[^=]{1,2000}?)(?<!SYSTEM)\s{1,100}(\w+=|$)""",
      """\Wsproc=({process}({process_directory}.*?)[\\\/]{0,2000}({process_name}[^\\\/=]{1,2000}?))\s{1,100}(\w+=|$)""",
      """\Wdhost=({dest_host}.+?)\s{1,100}(\w+=|$)""",
      """\Wdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
      """\Wrequest=({malware_file_name}file:.+?)\s{1,100}(\w+=|$)""",
      """\Wrequest=(?!file:)({malware_url}.+?)\s{1,100}(\w+=|$)""",
      """\Wdvc=({host}.+?)\s{1,100}(\w+=|$)""",
      """\Wdvchost=({host}.+?)\s{1,100}(\w+=|$)"""
    ]
    DupFields = [ "process_directory->directory" ]
  }
```