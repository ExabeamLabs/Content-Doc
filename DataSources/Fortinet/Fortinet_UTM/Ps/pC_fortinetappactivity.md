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
    """\Wdevname="{0,20}({host}[\w.-]{1,2000})"""",
    """\Wsubtype="{0,20}({event_subtype}[^"]{1,2000}?)"{0,20}(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wuser="({user}[^"]{1,2000}?)"""",
    """\Wsrcip=({src_ip}[a-fA-F\d.:]{1,2000})\s""",
    """\Wdstip=({dest_ip}[a-fA-F\d.:]{1,2000})\s""",
    """\Wapp="({app}[^"]{1,2000})"""",
    """\Waction="{0,20}({activity}[^"]{1,2000}?)"{0,20}(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wmsg="({additional_info}[^"]{1,2000})"""",
    """\Wauthserver="({auth_server}[^"]{1,2000})"""",
    """\Wsrcport=({src_port}\d{1,100})""",
    """\Wdstport=({dest_port}\d{1,100})""",
    """\Whostname="({web_domain}[^"]{1,2000})"""",
    """\Wservice="({protocol}[^"]{1,2000})"""",
    """\Wurl="({uri_path}[^"]{1,2000})"""",
    """\Wappcat="({category}[^"]{1,2000})"""",
    """\Wsubtype="({event_name}[^"]{1,2000})""""
  ]
  DupFields = ["activity->action"]


}
```