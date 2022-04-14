#### Parser Content
```Java
{
Name = leef-carbonblack-process-alert
  Vendor = VMware
  Product = Carbon Black EDR
  Lms = QRadar
  DataType = "process-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """LEEF:""", """|CB|""", """watchlist.storage.hit.process""", """process_name=""" ]
  Fields = [
    """\Wstart=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)\s""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\Wusername=((({domain}[^\\\s]{1,2000})\\\\)?({user}[^\s]{1,2000}))""",
    """\Wprocess_name=({process_name}[^=]{1,2000}?)\s{0,100}(([\w_]{1,2000}=)|$)""",
    """\Wpath=({process}({directory}[^=]{0,2000}?[\\\/]{1,2000})?[^\\\/=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wtype=({alert_name}watchlist.storage.hit.process)""",
    """\Wwatchlist_name=({alert_name}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wtype=({alert_type}watchlist.storage.hit.process)""",
    """\Wcmdline=(|({command_line}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wprocess_pid=({pid}[^\s]{1,2000})"""
  ]


}
```