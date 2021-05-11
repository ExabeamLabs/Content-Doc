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
     """devTime=({time}\w+\s{1,100}\d\d \d\d\d\d \d\d:\d\d:\d\d \S+)""",
     """\Wdvc=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wshost=(({src_ip}[A-Fa-f:\d.]+)|({src_host}[^\s]+))""",
    """\Wdhost=({dest_ip}[^\s]+)""",
    """\Wdst=({src_ip}[a-fA-F\d.:]+)""",
    """\WdstPort=({src_port}\d{1,100})""",
    """\Wsrc=({dest_ip}[a-fA-F\d.:]+)""",
    """\WsrcPort=({dest_port}\d{1,100})""",
    """deviceMacAddress=({src_mac}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """msg=({alert_name}.+?)\s{1,100}\w+=""",
    """proto=({protocol}[^\s]+)""",
    """ptype=({alert_type}[^\s]+)""",
    """sev=({alert_severity}\d{1,100})""",
    """act=({outcome}.+?)\s{1,100}\w+=""",
    """suid=([^\\\/]+(\\|\/))?(anonymous|({user_email}[^@]+@[^\s]+)|({user}[^\s]+))""",
    """d(U|u)ser(\d{1,100})?=([^\\]+\\)?({user}[^\s]+)"""
    """s(U|u)ser(\d{1,100})?=([^\\]+\\)?({user}[^\s]+)"""
  ]
}
```