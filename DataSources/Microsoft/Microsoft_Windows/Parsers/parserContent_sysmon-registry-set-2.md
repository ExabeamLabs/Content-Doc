#### Parser Content
```Java
{
Name = sysmon-registry-set-2
  Conditions = [ """Registry value set: """, """ UtcTime: """ ]
  DataType = "file-operations"
  Fields = ${MicrosoftParserTemplates.sysmon-process-events.Fields}[
    """\s+Image:\s*({file_path}({file_parent}(?:(\w+:)?[^:]+)?[\\\/])?({file_name}.+?))\s+\w+:""",
    """TargetObject:\s*({object}.+?)\s+(\w+:|$)"""
  ]
}
sysmon-process-events = {
  Vendor = Microsoft
  Product = Microsoft Sysmon
  Lms = Splunk
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [ 
    """UtcTime:\s*({time}\d\d\d\d\-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """User=({user}.+?)\s+(\w+=|$)""",
    """Domain=({domain}.+?)\s+(\w+=|$)""",
    """User:\s*(?:({domain}[^\\]+)\\)?({user}.+?)\s+LogonGuid:""",
    """Sid=\s*({user_sid}[^\s]+)""",
    """LogonId:\s*({logon_id}[^\s]+)""",
    """Hashes:.*?,?MD5=({md5}[^\s,]+)""",
    """\sProcessGuid:\s*\{({process_guid}[^\s\}]+)""",
    """\sProcessId:\s*({pid}\d+)""",
    """ParentProcessGuid:\s*\{({parent_process_guid}[^\s\}]+)""",
    """CommandLine:\s*"*({command_line}.+?)"*\s*CurrentDirectory:""",
    """\s+Image:\s*({process}({directory}(?:(\w+:)?[^:]+)?[\\\/])?({process_name}.+?))\s+(\w+:|$)""",
    """\s+Image:\s*({process}({directory}(?:(\w+:)?[^:]+)?[\\\/])?({process_name}.+?))\s+CommandLine:""",
    """\s+Image:\s*({process}({directory}(?:(\w+:)?[^:]+)?[\\\/])?({process_name}.+?))\s+FileVersion:""",
    """\s+ParentImage:\s*({parent_process}({parent_directory}(?:(\w+:)?[^:]+)?[\\\/])?({parent_process_name}.+?))\s+ParentCommandLine:"""
  ]

```