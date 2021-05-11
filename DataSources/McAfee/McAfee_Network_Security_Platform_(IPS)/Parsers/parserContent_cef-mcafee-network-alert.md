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
    """CEF:([^\|]*\|){5}({protocol}[^:\|]+):\s{0,100}({alert_name}[^\|]+)\|({alert_severity}[^\|]+)""",
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=({host}\S+)""",
    """\Wdvchost=({host}\S+)""",
    """\WeventId=({alert_id}\d{1,100})""",
    """\Wcat=({alert_type}.+?)\s{1,100}(\w+=|$)""",
    """\Wact=(Unknown|({outcome}.+?))\s{1,100}(\w+=|$)""",
    """\Wapp=({app_protocol}.+?)\s{1,100}(\w+=|$)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wshost=({src_host}[\w\-.]+)""",
    """\Wdhost=({dest_host}[\w\-.]+)""",
    """\Wspt=({src_port}\d{1,100})""",
    """\Wdpt=({dest_port}\d{1,100})""",
  ]
  DupFields = [ "alert_name->policy" ]
}
```