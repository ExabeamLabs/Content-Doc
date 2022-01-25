#### Parser Content
```Java
{
Name = cef-observeit-app-activity
  Vendor = ObserveIT
  Product = ObserveIT
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|ObserveIT|ObserveIT|""" ]
  Fields = [
    """\Wmsg=(|({additional_info}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcat=(|({activity}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wrt=({time}\d{1,100})""",
    """({app}ObserveIT)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wdvc=(|({host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdvchost=(|({host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs2=(|({os}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WdestinationServiceName =(|({object}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdhost=(|({dest_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wshost=\(?(|({src_host}[\w\-.]{1,2000}))\)?(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wduser=(|({user}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdntdom=(|({domain}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
  ]


}
```