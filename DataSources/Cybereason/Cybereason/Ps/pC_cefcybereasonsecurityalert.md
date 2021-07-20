#### Parser Content
```Java
{
Name = cef-cybereason-security-alert
  Vendor = Cybereason
  Product = Cybereason
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """destinationServiceName=Cybereason""", """security-threat-detected""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\Wact=(|({action}[^=]{1,2000}]?))(\s{1,100}\w+=|\s{0,100}$)""",
    """"detectionType":\{[^=]{1,2000}?"values":\["({alert_type}[^"]{1,2000})"""",
    """\Wdhost=(|({dest_host}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wduser=(|(({domain}[^\\\/=]{1,2000})[\\\/]{1,2000})?(system|({user}[^=\\\/]{1,2000}?)))(\s{1,100}\w+=|\s{0,100}$)""",
    """"creationTime":\{[^]}]{1,2000}?"values":\["({time}\d{1,2000})"""",
    """\Wmsg=(|({additional_info}({alert_name}[^\.]{1,2000}).+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """"malopActivityTypes":\{"[^]}]{1,2000}?"values":\["({threat_category}[^"]{1,2000})"""",
  ]
}
```