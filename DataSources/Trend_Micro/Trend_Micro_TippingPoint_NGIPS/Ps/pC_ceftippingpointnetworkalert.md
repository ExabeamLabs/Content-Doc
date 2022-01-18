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
    """\Wdvc=({host}\S+)\s{0,100}(\w+=|$)""",
    """\Wdvchost=({host}\S+)\s{0,100}(\w+=|$)""",
    """\Wrt=({time}\d{1,100})""",
    """CEF:([^\|]{0,2000}\|){5}({alert_type}[^\s:]{1,2000}):?\s{0,100}\-?\s{0,100}({alert_name}[^\|]{1,2000})\|({alert_severity}\d{1,100})""",
    """\WeventId=({alert_id}\d{1,100})""",
    """\Wshost=({src_host}\S+)\s{0,100}(\w+=|$)""",
    """\Wdhost=({dest_host}\S+)\s{0,100}(\w+=|$)""",
    """\Wsrc=({src_ip}[\da-fA-F\.:]{1,2000})""",
    """\Wcs5=({src_ip}[\da-fA-F\.:]{1,2000})""",
    """\Wdst=({dest_ip}[\da-fA-F\.:]{1,2000})""",
    """\WdeviceSeverity=({alert_severity}.+?)\s{0,100}(\w+=|$)"""
  ]


}
```