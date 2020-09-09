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
    """\Wmsg=(|({additional_info}.+?))(\s+\w+=|\s*$)""",
    """\Wcat=(|({activity}.+?))(\s+\w+=|\s*$)""",
    """\Wrt=({time}\d+)""",
    """({app}ObserveIT)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wdvc=(|({host}.+?))(\s+\w+=|\s*$)""",
    """\Wdvchost=(|({host}.+?))(\s+\w+=|\s*$)""",
    """\Wcs2=(|({os}.+?))(\s+\w+=|\s*$)""",
    """\WdestinationServiceName=(|({object}.+?))(\s+\w+=|\s*$)""",
    """\Wdhost=(|({dest_host}.+?))(\s+\w+=|\s*$)""",
    """\Wshost=\(?(|({src_host}[\w\-.]+))\)?(\s+\w+=|\s*$)""",
    """\Wduser=(|({user}.+?))(\s+\w+=|\s*$)""",
    """\Wdntdom=(|({domain}.+?))(\s+\w+=|\s*$)""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]+)""",
  ]
}
```