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
    """\Wdhost=({host}[\w\-\.]+)\s*(\w+=|$)""",
    """\Wdvchost=({host}[\w\-\.]+)\s*(\w+=|$)""",
    """\Wdst=({dest_ip}[a-fA-F:\.\d]+)\s*(\w+=|$)""",
    """({event_code}4688)""",
    """\Wduser=(?:-|({user}[^\s]+))\s*(\w+=|$)""",
    """\Wdntdom=(?:-|({domain}[^\s]+))\s*(\w+=|$)""",
    """\WdeviceNtDomain=(?:-|({domain}[^\s]+))\s*(\w+=|$)""",
    """\Wdproc=({process}({directory}(?:[^"]+?)?[\\\/])?({process_name}[^\\\/]+?))\s*(\w+=|$)""",
    """\Wdproc=({path}.+?)\s*(\w+=|$)""",
    """\Wduid=({logon_id}[^\s]+)\s*(\w+=|$)""",
    """\Wcs2=({activity_type}.+?)\s*(\w+=|$)""",
    """\Wcs3=({process_guid}[^\s]+)\s*(\w+=|$)""",
    """\Wcs4=({command_line}.+?)\s*(\w+=|$)""",
    """\Wcs5=({parent_process_guid}[^\s]+)\s*(\w+=|$)""",
  ]
  DupFields = [ "host->dest_host", "process_guid->pid","directory->process_directory" ]
}
```