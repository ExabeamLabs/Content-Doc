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
    """\Wshost=(({src_ip}[A-Fa-f:\d.]{1,2000})|({src_host}[^\s]{1,2000}))""",
    """\Wdhost=({dest_ip}[^\s]{1,2000})""",
    """\Wdst=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\WdstPort=({src_port}\d{1,100})""",
    """\Wsrc=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\WsrcPort=({dest_port}\d{1,100})""",
    """deviceMacAddress=({src_mac}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """msg=({alert_name}.+?)\s{1,100}\w+=""",
    """proto=({protocol}[^\s]{1,2000})""",
    """ptype=({alert_type}[^\s]{1,2000})""",
    """sev=({alert_severity}\d{1,100})""",
    """act=({outcome}.+?)\s{1,100}\w+=""",
    """suid=([^\\\/]{1,2000}(\\|\/))?(anonymous|({user_email}[^@]{1,2000}@[^\s]{1,2000})|({user}[^\s]{1,2000}))""",
    """d(U|u)ser(\d{1,100})?=([^\\]{1,2000}\\)?({user}[^\s]{1,2000})"""
    """s(U|u)ser(\d{1,100})?=([^\\]{1,2000}\\)?({user}[^\s]{1,2000})"""
  ]
}
```