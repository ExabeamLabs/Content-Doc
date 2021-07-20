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
    """CEF:([^\|]{0,2000}\|){5}({protocol}[^:\|]{1,2000}):\s{0,100}({alert_name}[^\|]{1,2000})\|({alert_severity}[^\|]{1,2000})""",
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=({host}\S+)""",
    """\Wdvchost=({host}\S+)""",
    """\WeventId=({alert_id}\d{1,100})""",
    """\Wcat=({alert_type}.+?)\s{1,100}(\w+=|$)""",
    """\Wact=(Unknown|({outcome}.+?))\s{1,100}(\w+=|$)""",
    """\Wapp=({app_protocol}.+?)\s{1,100}(\w+=|$)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wshost=({src_host}[\w\-.]{1,2000})""",
    """\Wdhost=({dest_host}[\w\-.]{1,2000})""",
    """\Wspt=({src_port}\d{1,100})""",
    """\Wdpt=({dest_port}\d{1,100})""",
  ]
  DupFields = [ "alert_name->policy" ]
}
```