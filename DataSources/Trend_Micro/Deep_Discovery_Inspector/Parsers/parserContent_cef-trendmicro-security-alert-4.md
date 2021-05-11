#### Parser Content
```Java
{
Name = cef-trendmicro-security-alert-4
  Vendor = Trend Micro
  Product = Deep Discovery Inspector
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss zZ"
  Conditions = [ """CEF:""", """|Trend Micro|Deep Discovery Inspector|""", """hostSeverity=""", """peerIp=""" ]
  Fields = [
    """CEF:([^\|]*\|){5}({alert_name}[^\|]+)\|({alert_severity}[^\|]+)""",
    """CEF:([^\|]*\|){5}({alert_type}[^\|]+)\|""",
    """\WeventId=({alert_id}\d{1,100})""",
    """\Wdvc=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdvchost=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wrt=({time}\w+\s{1,100}\d\d \d\d\d\d \d\d:\d\d:\d\d \S+)""",
    """\Wshost=(({src_ip}[A-Fa-f:\d.]+)|({src_host}[^\s]+))""",
    """\Wdhost=({malware_url}[^\s]+)""",
    """\Wapp=({app}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdst=({src_ip}[a-fA-F\d.:]+)""",
    """\Wdpt=({src_port}\d{1,100})""",
    """\Wsrc=({dest_ip}[a-fA-F\d.:]+)""",
    """\Wspt=({dest_port}\d{1,100})""",
    """\Wact=({outcome}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsmac=({src_mac}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\WmalType=((?i)(OTHERS)|({alert_type}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WmalType=((?i)(OTHERS)|({alert_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WruleName=({alert_name}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\WcompressedFileHash=({md5}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\WhostSeverity=({alert_severity}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\WpeerIp=({src_ip}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\WinterestedIp=({dest_ip}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
  ]
}
```