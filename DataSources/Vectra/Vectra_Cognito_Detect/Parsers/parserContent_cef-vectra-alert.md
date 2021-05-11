#### Parser Content
```Java
{
Name = cef-vectra-alert
  Vendor = Vectra
  Product = Vectra Cognito Detect
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """|Vectra Networks|X Series|""" ]
  Fields = [
    """CEF.+?([^|]+\|){4}({alert_type}[^|]+)""",
    """CEF.+?([^|]+\|){5}({alert_name}[^|]+)""",
    """\Wcat=({additional_info}.*?)(\s{1,100}\w+=|\s{0,100}$|$)""",
    """\Wdvc=({host}[^\s]+)(\s{1,100}\w+=|\s{0,100}$|$)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\Wshost=({src_host}[^\s]+)(\s{1,100}\w+=|\s{0,100}$|$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wdhost=({dest_host}[^\s]+)(\s{1,100}\w+=|\s{0,100}$|$)""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]+)""",
    """\Wstart=({time}\d{1,100})""",
    """\WexternalId=({alert_id}.+?)\s{1,100}(\w+=|$)""",
    """\WflexNumber2=({certainity}.+?)\s{1,100}(\w+=|$)""",
    """\WflexNumber1=({threat_id}.+?)\s{1,100}(\w+=|$)""",
  ]
}
```