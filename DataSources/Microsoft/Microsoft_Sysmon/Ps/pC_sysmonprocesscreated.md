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
  Fields = [ 
    """Hostname":"({host}[^"]{1,2000}?)"""",
    """UtcTime:\s{0,100}({time}\d\d\d\d\-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\sComputer(?:Name)?\s{0,100}=\s{0,100}"?({host}[^\s"]{1,2000})""",
    """Message\s{0,100}=\s{0,100}"?({activity_type}[^:]{1,2000})""",
    """User=({user}.+?)\s{1,100}(\w+=|$)""",
    """Domain=({domain}.+?)\s{1,100}(\w+=|$)""",
    """User:\s{0,100}(?:({domain}[^\\]{1,2000})\\)?({user}.+?)\s{1,100}LogonGuid:""",
    """Sid=\s{0,100}({user_sid}[^\s]{1,2000})""",
    """LogonId:\s{0,100}({logon_id}[^\s]{1,2000})""",
    """Hashes:.*?,?MD5=({md5}[^\s,]{1,2000})""",
    """ProcessGuid:\s{0,100}\{({process_guid}[^\s\}]{1,2000})""",
    """ProcessId:\s{0,100}({pid}\d{1,100})""",
    """ParentProcessGuid:\s{0,100}\{({parent_process_guid}[^\s\}]{1,2000})""",
    """CommandLine:\s{0,100}({command_line}.+?)\s{0,100}CurrentDirectory:""",
    """\s{1,100}Image:\s{0,100}({process}({directory}(?:(\w+:)?[^:]{1,2000})?[\\\/])?({process_name}.+?))\s{1,100}CommandLine:""",
    """\s{1,100}Image:\s{0,100}({process}({directory}(?:(\w+:)?[^:]{1,2000})?[\\\/])?({process_name}.+?))\s{1,100}FileVersion:""",
    """\s{1,100}ParentImage:\s{0,100}({parent_process}({parent_directory}(?:(\w+:)?[^:]{1,2000})?[\\\/])?({parent_process_name}.+?))\s{1,100}ParentCommandLine:""",
    """ParentImage:\s{0,100}({parent_process}({parent_process_directory}.*?)({parent_process_name}[^.\\]{1,2000}\.exe))\s{0,100}\w+:""",
    """ParentCommandLine:\s{0,100}({parent_command_line}.+)\s{0,100}""",
    """CommandLine:.*\s{1,100}config\s{1,100}({service_name}\S+)""",
    """binPath=\s{0,100}({service_command_line}(?:\"(.+)\")|(?:(\S+)))\s{0,100}CurrentDirectory:""",
    """CommandLine:.*\s{1,100}({parameter_sct}\S+\.sct)""",
    """CommandLine:.*\s{1,100}"({parameter_sct}.+\.sct)"""",
    """CommandLine:.*\s{1,100}({parameter_hta}\S+\.hta)""",
    """CommandLine:.*\s{1,100}"({parameter_hta}.+\.hta)"""",
    """CommandLine:.*\s{1,100}({parameter_xml}\S+\.xml)""",
    """CommandLine:.*\s{1,100}"({parameter_xml}.+\.xml)"""",
    """CommandLine:.*\s{1,100}({parameter_csproj}\S+\.csproj)""",
    """CommandLine:.*\s{1,100}"({parameter_csproj}.+\.csproj)"""",
    """CommandLine:.+?\/u\s{0,100}["\s]({parameter_exe}.+?\.exe)\s{1,100}CurrentDirectory:""",
    """CommandLine:.+?\/u\s{0,100}["\s]({parameter_dll}.+?\.dll)\s{1,100}CurrentDirectory:"""
    """IntegrityLevel:\s{0,100}({integrity}.+?)\s{0,100}\w+:""",
    """EventID":({event_code}\d{1,100}),""",
    """"Image":"({process}(({directory}[^"]{0,2000}?)[\\\/]{1,20})?({process_name}[^"\\\/]{1,2000}))"""",
    """"ParentImage":"({parent_process}(({parent_directory}[^"]{0,2000}?)[\\\/]{1,20})?({parent_process_name}[^"\\\/]{1,2000}))""""
  ]
  DupFields = [ "host->dest_host", "directory->process_directory", "process->path" ]


}
```