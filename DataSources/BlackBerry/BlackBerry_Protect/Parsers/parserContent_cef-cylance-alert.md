#### Parser Content
```Java
{
Name = cef-cylance-alert
  Vendor = BlackBerry
  Product = BlackBerry Protect
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Cylance|PROTECT|""", """eventId="""]
  Fields = [
    """\Wdvchost=({host}[\w\-.]+)""",
    """\Wrt=({time}\d+)""",
    """\WeventId=({alert_id}\d+)""",
    """\Wdhost=({dest_host}[\w\-.]+)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wduser=\(?((({domain}[^\\\s\(\),]+)\\+)?(SYSTEM|({user}[^\\\s\(\),]+)))[^\)]*\)?\s""",
    """CEF:([^\|]*\|){6}(Unknown|({alert_severity}[^\|]+))""",
    """CEF:([^\|]*\|){5}({alert_name}[^\|]+)""",
    """\Wcs4=({alert_name}.+?)\s+(\w+=|$)""",
    """\WfilePath=(|({malware_url}.+?))\s+(\w+=|$)""",
    """\Wmsg=(|({additional_info}.+?))\s+(\w+=|$)""",
    """\Wact=(|({outcome}.+?))\s+(\w+=|$)""",
    """\Wad\.Process_,Name=(|({process}({directory}(?:(\w+:)*([\\\/]+[^\\\/"]+?)+?)?[\\\/]+)({process_name}[^"\\\/]+?)))\s+(\w+=|$)""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```