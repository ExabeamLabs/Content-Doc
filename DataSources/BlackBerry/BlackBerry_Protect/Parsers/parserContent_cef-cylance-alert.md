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
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\Wrt=({time}\d{1,100})""",
    """\WeventId=({alert_id}\d{1,100})""",
    """\Wdhost=({dest_host}[\w\-.]{1,2000})""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wduser=\(?((({domain}[^\\\s\(\),]{1,2000})\\+)?(SYSTEM|({user}[^\\\s\(\),]{1,2000})))[^\)]{0,2000}\)?\s""",
    """CEF:([^\|]{0,2000}\|){6}(Unknown|({alert_severity}[^\|]{1,2000}))""",
    """CEF:([^\|]{0,2000}\|){5}({alert_name}[^\|]{1,2000})""",
    """\Wcs4=({alert_name}.+?)\s{1,100}(\w+=|$)""",
    """\WfilePath=(|({malware_url}.+?))\s{1,100}(\w+=|$)""",
    """\Wmsg=(|({additional_info}.+?))\s{1,100}(\w+=|$)""",
    """\Wact=(|({outcome}.+?))\s{1,100}(\w+=|$)""",
    """\Wad\.Process_,Name=(|({process}({directory}(?:(\w+:)*([\\\/]{1,2000}[^\\\/"]{1,2000}?)+?)?[\\\/]{1,2000})({process_name}[^"\\\/]{1,2000}?)))\s{1,100}(\w+=|$)""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```