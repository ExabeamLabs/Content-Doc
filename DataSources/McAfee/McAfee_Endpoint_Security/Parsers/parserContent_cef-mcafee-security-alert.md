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
      """CEF:([^\|]*\|){5}({alert_name}[^\|]+)\|""",
      """CEF:([^\|]*\|){6}({alert_severity}[^\|]+)\|""",
      """\Wcat=({alert_type}.+?)\s{1,100}(\w+=|$)""",
      """\Wrt=({time}\d{1,100})""",
      """\Wshost=({src_host}.+?)\s{1,100}(\w+=|$)""",
      """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
      """\Wsuser=(?!NT AUTHORITY)(({domain}[^\\\/=]+?)[\\\/]+)?({user}[^=]+?)(?<!SYSTEM)\s{1,100}(\w+=|$)""",
      """\Wsproc=({process}({process_directory}.*?)[\\\/]*({process_name}[^\\\/=]+?))\s{1,100}(\w+=|$)""",
      """\Wdhost=({dest_host}.+?)\s{1,100}(\w+=|$)""",
      """\Wdst=({dest_ip}[a-fA-F\d.:]+)""",
      """\Wrequest=({malware_file_name}file:.+?)\s{1,100}(\w+=|$)""",
      """\Wrequest=(?!file:)({malware_url}.+?)\s{1,100}(\w+=|$)""",
      """\Wdvc=({host}.+?)\s{1,100}(\w+=|$)""",
      """\Wdvchost=({host}.+?)\s{1,100}(\w+=|$)"""
    ]
    DupFields = [ "process_directory->directory" ]
  }
```