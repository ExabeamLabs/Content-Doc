#### Parser Content
```Java
{
Name = cef-carbonblack-alert-2
  Vendor = VMware
  Product = VMware Carbon Black EDR
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|CarbonBlack|Response|""", """feed.ingress.hit.process""" ]
  Fields = [
    """({host}[\w.\-]+):\s+CEF:([^\|]*\|){5}({alert_name}[^\|]+)""",
    """\Wend=({time}\d+)""",
    """\Wmsg=(|({alert_type}.+?))(\s+\w+=|\s*$)""",
    """\Wsuser=(|({user}.+?))(\s+\w+=|\s*$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\WdeviceProcessName=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wshost=(|({src_host}.+?))(\s+\w+=|\s*$)""",
    """\Wrequest=(|({malware_url}.+?))(\s+\w+=|\s*$)""",
    """\WrequestUrlPort=({dest_port}\d+)""",
  ]
  DupFields = ["host->dest_host"]
}
```