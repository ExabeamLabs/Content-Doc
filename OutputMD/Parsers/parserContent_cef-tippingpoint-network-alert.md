#### Parser Content
```Java
{
Name = cef-tippingPoint-network-alert
  Vendor = Trend Micro
  Product = Trend Micro TippingPoint NGIPS
  Lms = ArcSight
  DataType = "network-alert"
  TimeFormat = "epoch"
  Conditions = [ """|TippingPoint|SMS|""", """eventId=""" ]
  Fields = [
    """\Wdvc=({host}\S+)\s*(\w+=|$)""",
    """\Wdvchost=({host}\S+)\s*(\w+=|$)""",
    """\Wrt=({time}\d+)""",
    """CEF:([^\|]*\|){5}({alert_type}[^\s:]+):?\s*\-?\s*({alert_name}[^\|]+)\|({alert_severity}\d+)""",
    """\WeventId=({alert_id}\d+)""",
    """\Wshost=({src_host}\S+)\s*(\w+=|$)""",
    """\Wdhost=({dest_host}\S+)\s*(\w+=|$)""",
    """\Wsrc=({src_ip}[\da-fA-F\.:]+)""",
    """\Wcs5=({src_ip}[\da-fA-F\.:]+)""",
    """\Wdst=({dest_ip}[\da-fA-F\.:]+)""",
    """\WdeviceSeverity=({alert_severity}.+?)\s*(\w+=|$)"""
  ]
}
```