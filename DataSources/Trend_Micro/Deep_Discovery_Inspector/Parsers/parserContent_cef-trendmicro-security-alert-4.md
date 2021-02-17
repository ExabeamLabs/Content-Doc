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
    """\WeventId=({alert_id}\d+)""",
    """\Wdvc=({host}.+?)(\s+\w+=|\s*$)""",
    """\Wdvchost=({host}.+?)(\s+\w+=|\s*$)""",
    """\Wrt=({time}\w+\s+\d\d \d\d\d\d \d\d:\d\d:\d\d \S+)""",
    """\Wshost=(({src_ip}[A-Fa-f:\d.]+)|({src_host}[^\s]+))""",
    """\Wdhost=({malware_url}[^\s]+)""",
    """\Wapp=({app}.+?)(\s+\w+=|\s*$)""",
    """\Wdst=({src_ip}[a-fA-F\d.:]+)""",
    """\Wdpt=({src_port}\d+)""",
    """\Wsrc=({dest_ip}[a-fA-F\d.:]+)""",
    """\Wspt=({dest_port}\d+)""",
    """\Wact=({outcome}.+?)(\s+\w+=|\s*$)""",
    """\Wsmac=({src_mac}.+?)(\s+\w+=|\s*$)""",
    """\WmalType=((?i)(OTHERS)|({alert_type}.+?))(\s+\w+=|\s*$)""",
    """\WmalType=((?i)(OTHERS)|({alert_name}.+?))(\s+\w+=|\s*$)""",
    """\WruleName=({alert_name}.+?)(\s+\w+=|\s*$)""",
    """\WcompressedFileHash=({md5}.+?)(\s+\w+=|\s*$)""",
    """\WhostSeverity=({alert_severity}.+?)(\s+\w+=|\s*$)""",
    """\WpeerIp=({src_ip}.+?)(\s+\w+=|\s*$)""",
    """\WinterestedIp=({dest_ip}.+?)(\s+\w+=|\s*$)""",
  ]
}
```