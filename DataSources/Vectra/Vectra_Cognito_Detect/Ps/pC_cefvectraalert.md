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
    """CEF.+?([^|]{1,2000}\|){4}({alert_type}[^|]{1,2000})""",
    """CEF.+?([^|]{1,2000}\|){5}({alert_name}[^|]{1,2000})""",
    """\Wcat=({additional_info}.*?)(\s{1,100}\w+=|\s{0,100}$|$)""",
    """\Wdvc=({host}[^\s]{1,2000})(\s{1,100}\w+=|\s{0,100}$|$)""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\Wshost=({src_host}[^\s]{1,2000})(\s{1,100}\w+=|\s{0,100}$|$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wdhost=({dest_host}[^\s]{1,2000})(\s{1,100}\w+=|\s{0,100}$|$)""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wstart=({time}\d{1,100})""",
    """\WexternalId=({alert_id}.+?)\s{1,100}(\w+=|$)""",
    """\WflexNumber2=({certainity}.+?)\s{1,100}(\w+=|$)""",
    """\WflexNumber1=({threat_id}.+?)\s{1,100}(\w+=|$)""",
  ]


}
```