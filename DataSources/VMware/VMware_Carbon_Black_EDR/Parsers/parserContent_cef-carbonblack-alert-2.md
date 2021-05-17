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
    """({host}[\w.\-]{1,2000}):\s{1,100}CEF:([^\|]{0,2000}\|){5}({alert_name}[^\|]{1,2000})""",
    """\Wend=({time}\d{1,100})""",
    """\Wmsg=(|({alert_type}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsuser=(|({user}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\WdeviceProcessName=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wshost=(|({src_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wrequest=(|({malware_url}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WrequestUrlPort=({dest_port}\d{1,100})""",
  ]
  DupFields = ["host->dest_host"]
}
```