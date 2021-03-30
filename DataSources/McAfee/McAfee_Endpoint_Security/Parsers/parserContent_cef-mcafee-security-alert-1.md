#### Parser Content
```Java
{
Name = cef-mcafee-security-alert-1
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = ArcSight
    DataType = "alert"
    TimeFormat = "epoch"
    Conditions = [ """CEF:""", """|McAfee|Endpoint Security|""" ]
    Fields = [
      """CEF:([^\|]*\|){5}({alert_name}[^\|]+)\|""",
      """CEF:([^\|]*\|){6}({alert_severity}[^\|]+)\|""",
      """\Wcat=({alert_type}.+?)\s+(\w+=|$)""",
      """\WeventId=({alert_id}\d+)""",
      """\Wrt=({time}\d+)""",
      """\Wshost=({src_host}.+?)\s+(\w+=|$)""",
      """\Wc6a2=({src_ip}([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))\s+(\w+=|$)"""
      """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
      """\Wsuser=(?!NT AUTHORITY)(({domain}[^\\\/=]+?)[\\\/]+)?({user}[^=]+?)(?<!SYSTEM)\s+(\w+=|$)""",
      """\Wduser=(?!NT AUTHORITY)(({domain}[^\\\/=]+?)[\\\/]+)?({user}[^=]+?)(?<!SYSTEM)\s+(\w+=|$)""",
      """\Wsproc=({process}(|({process_directory}.*?))[\\\/]*({process_name}[^\\\/=]+?))\s+(\w+=|$)""",
      """\Wdproc=({process}(|({process_directory}.*?))[\\\/]*({process_name}[^\\\/=]+?))\s+(\w+=|$)""",
      """\Wdhost=({dest_host}.+?)\s+(\w+=|$)""",
      """\Wc6a3=({dest_ip}([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))\s+(\w+=|$)"""
      """\Wdst=({dest_ip}[a-fA-F\d.:]+)""",
      """\Wrequest=({malware_file_name}file:.+?)\s+(\w+=|$)""",
      """\Wrequest=(?!file:)({malware_url}.+?)\s+(\w+=|$)""",
      """\Wdvc=({host}.+?)\s+(\w+=|$)""",
      """\Wdvchost=({host}.+?)\s+(\w+=|$)""",
      """\Wcs1=(_|({additional_info}.*?))\s+(\w+=|$)""",
      """\WfilePath=({file_path}.+?)\s+(\w+=|$)""",
      """\Wdvcmac=({dest_mac}\w{2}-\w{2}-\w{2}-\w{2}-\w{2}-\w{2})\s""",
      """\Wact=({outcome}[^=]+?)\s+([\w\.-]+=|$)"""
    ]
    DupFields = [ "process_directory->directory" ]
  }
```