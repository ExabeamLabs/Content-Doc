#### Parser Content
```Java
{
Name = fortinet-app-activity
  Vendor = Fortinet
  Product = Fortinet UTM
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd' time='HH:mm:ss"
  Conditions = [ """subtype=""","""app-ctrl""", """eventtype=""","""app-ctrl-all""", """date=""" ]
  Fields = [
    """\Wdate=({time}\d\d\d\d-\d\d-\d\d time\=\d\d:\d\d:\d\d)""",
    """\Wdevname="*({host}.+?)"*(\s+\w+=|\s*$)""",
    """\Wsubtype="*({event_subtype}.+?)"*(\s+\w+=|\s*$)""",
    """\Wuser="({user}[^"]+?)"""",
    """\Wsrcip=({src_ip}[a-fA-F\d.:]+)""",
    """\Wdstip=({dest_ip}[a-fA-F\d.:]+)""",
    """\Wapp="({app}[^"]+)"""",
    """\Waction="*({activity}.+?)"*(\s+\w+=|\s*$)""",
    """\Wmsg="({additional_info}[^"]+)"""",
  ]
}
```