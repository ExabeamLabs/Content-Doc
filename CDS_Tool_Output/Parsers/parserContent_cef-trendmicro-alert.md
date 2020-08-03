#### Parser Content
```Java
{
Name = cef-trendmicro-alert
  Vendor = Trend Micro
  Product = Deep Discovery Inspector
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss zZ"
  Conditions = ["""Deep Discovery Inspector""" , """_DETECTION|"""]
  Fields = [
     """devTime=({time}\w+\s+\d\d \d\d\d\d \d\d:\d\d:\d\d \S+)""",
     """\Wdvc=({host}.+?)(\s+\w+=|\s*$)""",
    """\Wshost=(({src_ip}[A-Fa-f:\d.]+)|({src_host}[^\s]+))""",
    """\Wdhost=({dest_ip}[^\s]+)""",
    """\Wdst=({src_ip}[a-fA-F\d.:]+)""",
    """\WdstPort=({src_port}\d+)""",
    """\Wsrc=({dest_ip}[a-fA-F\d.:]+)""",
    """\WsrcPort=({dest_port}\d+)""",
    """deviceMacAddress=({src_mac}.+?)(\s+\w+=|\s*$)""",
    """msg=({alert_name}.+?)\s+\w+=""",
    """proto=({protocol}[^\s]+)""",
    """ptype=({alert_type}[^\s]+)""",
    """sev=({alert_severity}\d+)""",
    """act=({outcome}.+?)\s+\w+=""",
    """suid=([^\\\/]+(\\|\/))?(anonymous|({user_email}[^@]+@[^\s]+)|({user}[^\s]+))""",
    """d(U|u)ser(\d+)?=([^\\]+\\)?({user}[^\s]+)"""
    """s(U|u)ser(\d+)?=([^\\]+\\)?({user}[^\s]+)"""
  ]
}

{
  Name = cef-trendmicro-app-login
  Vendor = Trend Micro
  Product = Deep Discovery Inspector
  Lms = ArcSight
  DataType = "app-login"
  TimeFormat = "MMM dd yyyy HH:mm:ss zZ"
  Conditions = [ """CEF:""", """|Trend Micro|Deep Discovery Inspector|""", """dvc=""", """User logged on""" ]
  Fields = [
    """\Wdvc=({host}.+?)(\s+\w+=|\s*$)""",
    """\Wdvchost=({host}.+?)(\s+\w+=|\s*$)""",
    """\Wrt=({time}\w+\s+\d\d \d\d\d\d \d\d:\d\d:\d\d \S+)""",
    """\Wduser=({user}[^\s]+)""",
    """\Woutcome=({outcome}.+?)\s+(\w+=|$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
  ]
}
```