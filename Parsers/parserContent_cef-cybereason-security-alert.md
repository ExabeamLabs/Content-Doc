#### Parser Content
```Java
{
Name = cef-cybereason-security-alert
  Vendor = Cybereason
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """destinationServiceName=Cybereason""", """security-threat-detected""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """\Wact=(|({action}.+?))(\s+\w+=|\s*$)""",
    """\Wext_simpleValues_detectionType_values_0_=(|({alert_type}.+?))(\s+\w+=|\s*$)""",
    """\Wdhost=(|({dest_host}.+?))(\s+\w+=|\s*$)""",
    """\Wduser=(|(({domain}[^\\\/=]+)[\\\/]+)?({user}[^=\\\/]+?))(\s+\w+=|\s*$)""",
    """\Wext_simpleValues_creationTime_values_0_=({time}\d+)""",
    """\Wmsg=(|({additional_info}({alert_name}[^\.]+).+?))(\s+\w+=|\s*$)""",
    """\Wext_simpleValues_malopActivityTypes_values_0_=(|({threat_category}.+?))(\s+\w+=|\s*$)""",
  ]
}
```