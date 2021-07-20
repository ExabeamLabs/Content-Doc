#### Parser Content
```Java
{
Name = sysmon-process-created-2
  Conditions = [ """Process Create: """, """ ProcessGuid: """, """ ParentProcessGuid: """ ]
  DataType = "process-created"
  Fields = ${MicrosoftParserTemplates.sysmon-process-events.Fields}[
  ]
}
sysmon-process-events = {
  Vendor = Microsoft
  Product = Microsoft Sysmon
  Lms = Splunk
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [ 
    """UtcTime:\s{0,100}({time}\d\d\d\d\-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\sComputer="({host}[\w\-.]{1,2000})"""",
    """User=({user}.+?)\s{1,100}(\w+=|$)""",
    """Domain=({domain}.+?)\s{1,100}(\w+=|$)""",
    """User:\s{0,100}(?:(NT AUTHORITY|NT-AUTORITÄT|({domain}[^\\]{1,2000}))\\)?(SYSTEM|(NETWORK|LOCAL) SERVICE|({user}[^:]{1,2000}?))\s{1,100}LogonGuid:""",
    """Sid=\s{0,100}({user_sid}[^\s]{1,2000})""",
    """LogonId:\s{0,100}({logon_id}[^\s]{1,2000})""",
    """Hashes:\s{0,100},?MD5=({md5}[^\s,]{1,2000})""",
    """({event_name}Process Create)""",
    """\sProcessGuid:\s{0,100}\{({process_guid}[^\s\}]{1,2000})""",
    """\sProcessId:\s{0,100}({pid}\d{1,100})""",
    """ParentProcessGuid:\s{0,100}\{({parent_process_guid}[^\s\}]{1,2000})""",
    """CommandLine:\s{0,100}"{0,20}({command_line}.+?)\s{0,100}"{0,20}\s{0,100}CurrentDirectory:""",
    """\s{1,100}Image:\s{0,100}({process}({directory}(?:(\w+:)?[^:]{1,2000})?[\\\/])?({process_name}[^:]{1,2000}?))\s{1,100}(\w+:|$)""",
    """\s{1,100}Image:\s{0,100}({process}({directory}(?:(\w+:)?[^:]{1,2000})?[\\\/])?({process_name}[^:]{1,2000}?))\s{1,100}CommandLine:""",
    """\s{1,100}Image:\s{0,100}({process}({directory}(?:(\w+:)?[^:]{1,2000})?[\\\/])?({process_name}[^:]{1,2000}?))\s{1,100}FileVersion:""",
    """\s{1,100}ParentImage:\s{0,100}({parent_process}({parent_directory}(?:(\w+:)?[^:]{1,2000})?[\\\/])?({parent_process_name}[^:]{1,2000}?))\s{1,100}ParentCommandLine:"""
  ]

```