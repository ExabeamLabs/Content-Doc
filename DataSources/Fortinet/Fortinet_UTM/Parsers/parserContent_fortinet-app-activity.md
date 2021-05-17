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
    """\Wdevname="{0,20}({host}.+?)"{0,20}(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsubtype="{0,20}({event_subtype}.+?)"{0,20}(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wuser="({user}[^"]{1,2000}?)"""",
    """\Wsrcip=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wdstip=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wapp="({app}[^"]{1,2000})"""",
    """\Waction="{0,20}({activity}.+?)"{0,20}(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wmsg="({additional_info}[^"]{1,2000})"""",
  ]
}
```