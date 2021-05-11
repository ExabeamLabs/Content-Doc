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
    """\srt=({time}\d{1,100})""",
    """\s(deviceSeverity|severity)=({outcome}[^\s]+)""",
    """\sdhost=({host}.+?)(\s{1,100}[^\s]+=|\s{0,100}$)""",
    """\sdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """({event_code}4673)""",
    """\sduser=({user}.+?)(\s{1,100}[^\s]+=|\s{0,100}$)""",
    """\sdntdom=({domain}.+?)(\s{1,100}[^\s]+=|\s{0,100}$)""",
    """\sad.Service:Server=({object_server}.+?)(\s{1,100}[^\s]+=|\s{0,100}$)""",
    """\sduid=({login_id}[^\s]+)""",
    """(\s|:)Privileges(:|=)\s{0,100}({privileges}.+?)(\s{1,100}[^\s]+(=|:)|\s{0,100}$)""",
    """Process Name(:|=)\s{0,100}(?: |({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/";]+?)))[\s;]*Service Request Information(:|=)""",
    """\s{0,100}Account Name(:|=)\s{0,100}({user}.+?)[\s;]*Account Domain(:|=)""",
    """\s{0,100}Account Domain(:|=)\s{0,100}({domain}.+?)[\s;]*Logon ID(:|=)""",
    """\s{0,100}Logon ID(:|=)\s{0,100}({logon_id}.+?)[\s;]*Service(:|=)""",
    """\s{0,100}Server(:|=)\s{0,100}({object_server}.+?)[\s;]*Service Name""",
  ]
  DupFields = ["host->dest_host"]
}
```