#### Parser Content
```Java
{
Name = cef-4688
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-process-created"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """|Microsoft-Windows-Security-Auditing:4688|""", """|A new process has been created.|""" ]
  Fields = [
    """({event_name}A new process has been created)""",
    """\Wrt=({time}\d{13})""",
    """\Wdhost=({host}[\w\-\.]{1,2000})\s{0,100}(\w+=|$)""",
    """\Wdvchost=({host}[\w\-\.]{1,2000})\s{0,100}(\w+=|$)""",
    """\Wdst=({dest_ip}[a-fA-F:\.\d]{1,2000})\s{0,100}(\w+=|$)""",
    """({event_code}4688)""",
    """\Wduser=(?:-|({user}[^\s]{1,2000}))\s{0,100}(\w+=|$)""",
    """\Wdntdom=(?:-|({domain}[^\s]{1,2000}))\s{0,100}(\w+=|$)""",
    """\WdeviceNtDomain=(?:-|({domain}[^\s]{1,2000}))\s{0,100}(\w+=|$)""",
    """\Wdproc=({process}({directory}(?:[^"]{1,2000}?)?[\\\/])?({process_name}[^\\\/]{1,2000}?))\s{0,100}(\w+=|$)""",
    """\Wdproc=({path}.+?)\s{0,100}(\w+=|$)""",
    """\Wduid=({logon_id}[^\s]{1,2000})\s{0,100}(\w+=|$)""",
    """\Wcs2=({activity_type}.+?)\s{0,100}(\w+=|$)""",
    """\Wcs3=({process_guid}[^\s]{1,2000})\s{0,100}(\w+=|$)""",
    """\Wcs4=({command_line}.+?)\s{0,100}(\w+=|$)""",
    """\Wcs4=\s{0,100}(|-|(sc|((?:[^"]{1,2000})?[\\\/])?sc.exe)\s{0,100}(?:\\*[\w.\-]{1,2000})?\s{0,100}create\s{0,100}({service_name}.+?))\s{1,100}binPath= ({process}({directory}(?:[^"]{1,2000}?)?[\\\/])?({process_name}[^\\\/]{1,2000}?))\s{0,100}(\w+=|$)""",
    """\Wcs5=({parent_process_guid}[^\s]{1,2000})\s{0,100}(\w+=|$)""",
  ]
  DupFields = [ "host->dest_host", "process_guid->pid","directory->process_directory" ]
}
```