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
      """\Wcat=({alert_type}.+?)\s{1,100}(\w+=|$)""",
      """\WeventId=({alert_id}\d{1,100})""",
      """\Wrt=({time}\d{1,100})""",
      """\Wshost=({src_host}.+?)\s{1,100}(\w+=|$)""",
      """\Wc6a2=({src_ip}([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))\s{1,100}(\w+=|$)"""
      """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
      """\Wsuser=(?!NT AUTHORITY)(({domain}[^\\\/=]+?)[\\\/]+)?({user}[^=]+?)(?<!SYSTEM)\s{1,100}(\w+=|$)""",
      """\Wduser=(?!NT AUTHORITY)(({domain}[^\\\/=]+?)[\\\/]+)?({user}[^=]+?)(?<!SYSTEM)\s{1,100}(\w+=|$)""",
      """\Wsproc=({process}(|({process_directory}.*?))[\\\/]*({process_name}[^\\\/=]+?))\s{1,100}(\w+=|$)""",
      """\Wdproc=({process}(|({process_directory}.*?))[\\\/]*({process_name}[^\\\/=]+?))\s{1,100}(\w+=|$)""",
      """\Wdhost=({dest_host}.+?)\s{1,100}(\w+=|$)""",
      """\Wc6a3=({dest_ip}([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))\s{1,100}(\w+=|$)"""
      """\Wdst=({dest_ip}[a-fA-F\d.:]+)""",
      """\Wrequest=({malware_file_name}file:.+?)\s{1,100}(\w+=|$)""",
      """\Wrequest=(?!file:)({malware_url}.+?)\s{1,100}(\w+=|$)""",
      """\Wdvc=({host}.+?)\s{1,100}(\w+=|$)""",
      """\Wdvchost=({host}.+?)\s{1,100}(\w+=|$)""",
      """\Wcs1=(_|({additional_info}.*?))\s{1,100}(\w+=|$)""",
      """\WfilePath=({file_path}.+?)\s{1,100}(\w+=|$)""",
      """\Wdvcmac=({dest_mac}\w{2}-\w{2}-\w{2}-\w{2}-\w{2}-\w{2})\s""",
      """\Wact=({outcome}[^=]+?)\s{1,100}([\w\.-]+=|$)"""
    ]
    DupFields = [ "process_directory->directory" ]
  }
```