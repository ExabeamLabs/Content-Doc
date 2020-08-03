#### Parser Content
```Java
{
Name = cef-mcafee-network-alert
  Vendor = McAfee
  Product = McAfee Network Security Platform (IPS)
  DataType = network-alert
  Lms = Splunk
  TimeFormat = "epoch"
  Conditions = [ """CEF:""" , """|McAfee|Network Security Manager|""", """ src=""" ]
  Fields = [
    """CEF:([^\|]*\|){5}({protocol}[^:\|]+):\s*({alert_name}[^\|]+)\|({alert_severity}[^\|]+)""",
    """\Wrt=({time}\d+)""",
    """\Wdvc=({host}\S+)""",
    """\Wdvchost=({host}\S+)""",
    """\WeventId=({alert_id}\d+)""",
    """\Wcat=({alert_type}.+?)\s+(\w+=|$)""",
    """\Wact=(Unknown|({outcome}.+?))\s+(\w+=|$)""",
    """\Wapp=({app_protocol}.+?)\s+(\w+=|$)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wshost=({src_host}[\w\-.]+)""",
    """\Wdhost=({dest_host}[\w\-.]+)""",
    """\Wspt=({src_port}\d+)""",
    """\Wdpt=({dest_port}\d+)""",
  ]
  DupFields = [ "alert_name->policy" ]
}
```