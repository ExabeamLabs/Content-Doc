#### Parser Content
```Java
{
Name = avecto-process-created
    Vendor = Avecto
    Product = Avecto Defendpoint
    Lms = Splunk
    DataType = "process-created"
    IsHVF = true
    TimeFormat = "MM/dd/yyyy HH:mm:ss a"
    Conditions = [ """SourceName=Avecto Defendpoint Service""", """Message=Process started"""]
    Fields = [
      """exabeam_raw=({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
      """ComputerName=({host}[^\s]+)""",
      """Message=({activity_type}.+?)\s+Command Line:""",
      """User Name:\s*(?:[A-F\d\-]{36}|({user}.+?))\s+User Domain SID:""",
      """User Domain Name:\s*({domain}.*?)\s+User Domain Name""",
      """User SID:\s*({user_sid}.*?)\s+User Name""",
      """Token:\s*({token}.*?)\s+Token Description:""",
      """MD5:\s*({md5}[^\s]+)""",
      """Command Line:\s*({command_line}.+?)\s*Process Id:""",
      """Message Description:\s*(<.+?>)?\s+(Unique Process ID:)?\s*({process_guid}[^\s]+)\s+Workstyle ID:""",
      """Parent Process Unique ID:\s*(?:<None>|({parent_process_guid}[^\s]+))\s+Parent Process File Name:""",
      """File Name:\s*({process}({directory}(?:(\w+:)?[^:]+)?[\\\/])?({process_name}.+?))\s+Hash:"""
      """Parent Process File Name:\s*({parent_process}({parent_process_directory}(?:(\w+:)?[^:]+)?[\\\/])?({parent_process_name}.+?))\s+COM CLSID:"""
    ]
  DupFields = [ "host->dest_host","process_guid->pid","directory->process_directory" ]
  }
```