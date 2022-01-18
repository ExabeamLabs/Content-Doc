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
    """\s(deviceSeverity|severity)=({outcome}[^\s]{1,2000})""",
    """\sdhost=({host}.+?)(\s{1,100}[^\s]{1,2000}=|\s{0,100}$)""",
    """\sdst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """({event_code}4673)""",
    """\sduser=({user}.+?)(\s{1,100}[^\s]{1,2000}=|\s{0,100}$)""",
    """\sdntdom=({domain}.+?)(\s{1,100}[^\s]{1,2000}=|\s{0,100}$)""",
    """\sad.Service:Server=({object_server}.+?)(\s{1,100}[^\s]{1,2000}=|\s{0,100}$)""",
    """\sduid=({login_id}[^\s]{1,2000})""",
    """(\s|:)Privileges(:|=)\s{0,100}({privileges}.+?)(\s{1,100}[^\s]{1,2000}(=|:)|\s{0,100}$)""",
    """Process Name(:|=)\s{0,100}(?: |({process}({directory}(?:[^";]{1,2000})?[\\\/])?({process_name}[^\\\/";]{1,2000}?)))[\s;]{0,2000}Service Request Information(:|=)""",
    """\s{0,100}Account Name(:|=)\s{0,100}({user}.+?)[\s;]{0,2000}Account Domain(:|=)""",
    """\s{0,100}Account Domain(:|=)\s{0,100}({domain}.+?)[\s;]{0,2000}Logon ID(:|=)""",
    """\s{0,100}Logon ID(:|=)\s{0,100}({logon_id}.+?)[\s;]{0,2000}Service(:|=)""",
    """\s{0,100}Server(:|=)\s{0,100}({object_server}.+?)[\s;]{0,2000}Service Name""",
  ]
  DupFields = ["host->dest_host"]


}
```