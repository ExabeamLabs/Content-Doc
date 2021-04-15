#### Parser Content
```Java
{
Name = sysmon-process-created
  Vendor = Microsoft
  Product = Microsoft Sysmon
  Lms = Splunk
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Microsoft-Windows-Sysmon""", """Process Create:""", """Event ID: 1""" ]
  Fields = [ """UtcTime:\s*({time}\d\d\d\d\-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\sComputer(?:Name)?\s*=\s*"?({host}[^\s"]+)""",
    """Message\s*=\s*"?({activity_type}[^:]+)""",
    """User=({user}.+?)\s+(\w+=|$)""",
    """Domain=({domain}.+?)\s+(\w+=|$)""",
    """User:\s*(?:({domain}[^\\]+)\\)?({user}.+?)\s+LogonGuid:""",
    """Sid=\s*({user_sid}[^\s]+)""",
    """LogonId:\s*({logon_id}[^\s]+)""",
    """Hashes:.*?,?MD5=({md5}[^\s,]+)""",
    """ProcessGuid:\s*\{({process_guid}[^\s\}]+)""",
    """ProcessId:\s*({pid}\d+)""",
    """ParentProcessGuid:\s*\{({parent_process_guid}[^\s\}]+)""",
    """CommandLine:\s*({command_line}.+?)\s*CurrentDirectory:""",
    """\s+Image:\s*({process}({directory}(?:(\w+:)?[^:]+)?[\\\/])?({process_name}.+?))\s+CommandLine:""",
    """\s+Image:\s*({process}({directory}(?:(\w+:)?[^:]+)?[\\\/])?({process_name}.+?))\s+FileVersion:""",
    """\s+ParentImage:\s*({parent_process}({parent_directory}(?:(\w+:)?[^:]+)?[\\\/])?({parent_process_name}.+?))\s+ParentCommandLine:""",
    """ParentImage:\s*({parent_process}({parent_process_directory}.*?)({parent_process_name}[^.\\]+\.exe))\s*\w+:""",
    """ParentCommandLine:\s*({parent_command_line}.+)\s*""",
    """CommandLine:.*\s+config\s+({service_name}\S+)""",
    """binPath=\s*({service_command_line}(?:\"(.+)\")|(?:(\S+)))\s*CurrentDirectory:""",
    """CommandLine:.*\s+({parameter_sct}\S+\.sct)""",
    """CommandLine:.*\s+"({parameter_sct}.+\.sct)"""",
    """CommandLine:.*\s+({parameter_hta}\S+\.hta)""",
    """CommandLine:.*\s+"({parameter_hta}.+\.hta)"""",
    """CommandLine:.*\s+({parameter_xml}\S+\.xml)""",
    """CommandLine:.*\s+"({parameter_xml}.+\.xml)"""",
    """CommandLine:.*\s+({parameter_csproj}\S+\.csproj)""",
    """CommandLine:.*\s+"({parameter_csproj}.+\.csproj)"""",
    """CommandLine:.+?\/u\s*["\s]({parameter_exe}.+?\.exe)\s+CurrentDirectory:""",
    """CommandLine:.+?\/u\s*["\s]({parameter_dll}.+?\.dll)\s+CurrentDirectory:"""
    """IntegrityLevel:\s*({integrity}.+?)\s*\w+:"""
  ]
  DupFields = [ "host->dest_host", "directory->process_directory", "process->path" ]
}
```