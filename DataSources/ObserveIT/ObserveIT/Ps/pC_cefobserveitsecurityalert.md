#### Parser Content
```Java
{
Name = cef-observeit-security-alert
  Vendor = ObserveIT
  Product = ObserveIT
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|ObserveIT|ObserveIT|""", """|ObserveITAlert|""" ]
  Fields = [
    """\Wmsg=(|({additional_info}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcat=(|({activity}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wrt=({time}\d{1,100})""",
    """({app}ObserveIT)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wdvc=(|({host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdvchost=(|({host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs2=(|({os}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WdestinationServiceName=(|({object}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdhost=(|({dest_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wshost=\(?(|({src_host}[\w\-.]{1,2000}))\)?(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wduser=(|({user}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdntdom=(|({domain}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WdeviceSeverity=(|({alert_severity}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WeventId=(|({alert_id}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs5=(|({malware_url}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """CEF:([^\|]{0,2000}\|){5}({alert_name}[^\|]{1,2000})\|({alert_severity}[^\|]{1,2000})""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```