#### Parser Content
```Java
{
Name = avecto-process-created
    Vendor = BeyondTrust
    Product = BeyondTrust Privilege Management
    Lms = Splunk
    DataType = "process-created"
    IsHVF = true
    TimeFormat = "MM/dd/yyyy HH:mm:ss a"
    Conditions = [ """SourceName=Avecto Defendpoint Service""", """Message=Process started"""]
    Fields = [
      """exabeam_raw=({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
      """ComputerName=({host}[^\s]{1,2000})""",
      """Message=({activity_type}.+?)\s{1,100}Command Line:""",
      """User Name:\s{0,100}(?:[A-F\d\-]{36}|({user}.+?))\s{1,100}User Domain SID:""",
      """User Domain Name:\s{0,100}({domain}.*?)\s{1,100}User Domain Name""",
      """User SID:\s{0,100}({user_sid}.*?)\s{1,100}User Name""",
      """Token:\s{0,100}({token}.*?)\s{1,100}Token Description:""",
      """MD5:\s{0,100}({md5}[^\s]{1,2000})""",
      """Command Line:\s{0,100}({command_line}.+?)\s{0,100}Process Id:""",
      """Message Description:\s{0,100}(<.+?>)?\s{1,100}(Unique Process ID:)?\s{0,100}({process_guid}[^\s]{1,2000})\s{1,100}Workstyle ID:""",
      """Parent Process Unique ID:\s{0,100}(?:<None>|({parent_process_guid}[^\s]{1,2000}))\s{1,100}Parent Process File Name:""",
      """File Name:\s{0,100}({process}({directory}(?:(\w+:)?[^:]{1,2000})?[\\\/])?({process_name}.+?))\s{1,100}Hash:"""
      """Parent Process File Name:\s{0,100}({parent_process}({parent_process_directory}(?:(\w+:)?[^:]{1,2000})?[\\\/])?({parent_process_name}.+?))\s{1,100}COM CLSID:"""
    ]
  DupFields = [ "host->dest_host","process_guid->pid","directory->process_directory" ]
  }
```