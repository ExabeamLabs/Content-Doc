#### Parser Content
```Java
{
Name = cef-sysmon-file-write-1
  Conditions = [ """CEF:""", """|Microsoft Sysmon|Sysmon NXLog|""", """|SysmonTask-SYSMON_FILE_CREATE|File created|""" ]
}

${MicrosoftParserTemplates.cef-sysmon-file-write}{
  Name = cef-sysmon-file-write-2
  Conditions = [ """CEF:""", """|Microsoft Sysmon|Sysmon NXLog|""", """|SysmonTask-SYSMON_REG_SETVALUE|Registry value set|""" ]
}

${MicrosoftParserTemplates.xml-sysmon-activity}{
  Name = xml-sysmon-file-write
  DataType = "file-operations"
  IsHVF = true
  Conditions = [ """<EventID>13</EventID>""", """<Provider Name='Microsoft-Windows-Sysmon'""" ]
  Fields = ${MicrosoftParserTemplates.xml-sysmon-activity.Fields}[
    """<Data Name='TargetObject'>({file_path}(({file_parent}[^<>]+?)[\\\/]+)?({file_name}[^\\\/<>]*?(\.({file_ext}\w+))?))<\/Data>""",
  ]
  DupFields = [ "host->dest_host" ]
}

{
  Name = cef-sysmon-process-created
  Vendor = Microsoft
  Product = Sysmon
  Lms = ArcSight
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Microsoft Sysmon|Sysmon NXLog|""", """|SysmonTask-SYSMON_CREATE_PROCESS|Process Create|""" ]
  Fields = [
    """CEF:([^\|]*\|){5}({activity}[^\|]+)""",
    """({host}\S+) CEF:""",
    """\Wdvc=({host}[A-Fa-f:\d]+)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\Wrt=({time}\d+)""",
    """\WeventId=({event_id}\d+)""",
    """\WcategoryOutcome=\/({outcome}.+?)\s+(\w+=|$)""",
    """\Wdntdom=(NT AUTHORITY|({domain}\S+))""",
    """\Wduser=(SYSTEM|LOCAL|NETWORK SERVICE|({user}[^\s]+))""",
    """\Wsproc=({parent_process}({parent_directory}.*?)({parent_process_name}[^\\]+?))\s+(\w+=|$)""",
    """\Wdproc=(SYSTEM|FINANS|({process}({directory}.*?)({process_name}[^\\]+?)))\s+(\w+=|$)""",
    """\Wcs4=\{({parent_process_guid}[^\}]+)""",
    """\Wcs6=\{({process_guid}[^\}]+)""",
    """\Wdpid=({pid}\d+)""",
    """\Wcs1=({command_line}.+?)\s+(\w+=|$)""",
    """\Wcs2=({parent_command_line}.+?)\s+(\w+=|$)""",
    """\WfileHash=({md5}\S+)""",
  ]
  DupFields = [ "directory->process_directory" ]
}
```