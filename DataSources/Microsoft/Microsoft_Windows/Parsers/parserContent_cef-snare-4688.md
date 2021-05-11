#### Parser Content
```Java
{
Name = cef-snare-4688
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-process-created"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """|Microsoft-Windows-Security-Auditing:4688|""", """|Snare|""" ]
  Fields = [
    """({event_name}A new process has been created)""",
    """\Wrt=({time}\d{13})""",
    """\Wdhost=({host}[\w\-\.]+)\s{0,100}(\w+=|$)""",
    """\Wdvchost=({host}[\w\-\.]+)\s{0,100}(\w+=|$)""",
    """\Wdst=({dest_ip}[a-fA-F:\.\d]+)\s{0,100}(\w+=|$)""",
    """({event_code}4688)""",
    """\Wduser=(?:-|({user}[^\s]+))\s{0,100}(\w+=|$)""",
    """\Wdntdom=(?:-|({domain}[^\s]+))\s{0,100}(\w+=|$)""",
    """\WdeviceNtDomain=(?:-|({domain}[^\s]+))\s{0,100}(\w+=|$)""",
    """\Wdproc=({process}({directory}(?:[^"]+?)?[\\\/])?({process_name}[^\\\/]+?))\s{0,100}(\w+=|$)""",
    """\Wdproc=({path}.+?)\s{0,100}(\w+=|$)""",
    """\Wduid=({logon_id}[^\s]+)\s{0,100}(\w+=|$)""",
    """\Wcs2=({activity_type}.+?)\s{0,100}(\w+=|$)""",
    """\Wcs3=({process_guid}[^\s]+)\s{0,100}(\w+=|$)""",
    """\Wcs4=({command_line}.+?)\s{0,100}(\w+=|$)""",
    """\Wcs5=({parent_process_guid}[^\s]+)\s{0,100}(\w+=|$)""",
  ]
  DupFields = [ "host->dest_host", "process_guid->pid","directory->process_directory" ]
}
```