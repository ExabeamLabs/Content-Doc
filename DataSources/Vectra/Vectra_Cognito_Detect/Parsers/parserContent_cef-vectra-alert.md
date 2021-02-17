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
    """\Wcat=({additional_info}.*?)(\s+\w+=|\s*$|$)""",
    """\Wdvc=({host}[^\s]+)(\s+\w+=|\s*$|$)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\Wshost=({src_host}[^\s]+)(\s+\w+=|\s*$|$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wdhost=({dest_host}[^\s]+)(\s+\w+=|\s*$|$)""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]+)""",
    """\Wstart=({time}\d+)""",
    """\WexternalId=({alert_id}.+?)\s+(\w+=|$)""",
    """\WflexNumber2=({certainity}.+?)\s+(\w+=|$)""",
    """\WflexNumber1=({threat_id}.+?)\s+(\w+=|$)""",
  ]
}
```