#### Parser Content
```Java
{
Name = cef-snare-4673
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-privileged-access"
  TimeFormat = "epoch"
  Conditions = ["CEF:", "|Snare|", "|A privileged service was called", "Microsoft-Windows-Security-Auditing:4673|"]
  Fields = [
    """({event_name}A privileged service was called)""",
    """\srt=({time}\d+)""",
    """\s(deviceSeverity|severity)=({outcome}[^\s]+)""",
    """\sdhost=({host}.+?)(\s+[^\s]+=|\s*$)""",
    """\sdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """({event_code}4673)""",
    """\sduser=({user}.+?)(\s+[^\s]+=|\s*$)""",
    """\sdntdom=({domain}.+?)(\s+[^\s]+=|\s*$)""",
    """\sad.Service:Server=({object_server}.+?)(\s+[^\s]+=|\s*$)""",
    """\sduid=({login_id}[^\s]+)""",
    """(\s|:)Privileges(:|=)\s*({privileges}.+?)(\s+[^\s]+(=|:)|\s*$)""",
    """Process Name(:|=)\s*(?: |({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/";]+?)))[\s;]*Service Request Information(:|=)""",
    """\s*Account Name(:|=)\s*({user}.+?)[\s;]*Account Domain(:|=)""",
    """\s*Account Domain(:|=)\s*({domain}.+?)[\s;]*Logon ID(:|=)""",
    """\s*Logon ID(:|=)\s*({logon_id}.+?)[\s;]*Service(:|=)""",
    """\s*Server(:|=)\s*({object_server}.+?)[\s;]*Service Name""",
  ]
  DupFields = ["host->dest_host"]
}
```