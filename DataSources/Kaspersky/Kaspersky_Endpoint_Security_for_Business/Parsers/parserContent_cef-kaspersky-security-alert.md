#### Parser Content
```Java
{
Name = cef-kaspersky-security-alert
  Conditions = [ """CEF:""", """|Kaspersky|Kaspersky Endpoint Security""" ]
  Fields = ${KasperskyParserTemplates.cef-kaspersky-security-alert.Fields}[
    """\WcategoryDeviceGroup=(|({alert_type}.+?))(\s+\w+=|\s*$)""",
    """Action:\s*({action}[^\\]+)""",
    """fname=({file_path}({file_parent}[^=]*?[\\\/]+)?({file_name}[^\\\/=]+?(\.({file_ext}\w+))?))\s+\w+="""
    """requestClientApplication=({app}.+?)\s*\w+=""",
    """\Wdvchost=({src_host}[^\s]+)\s+\w+""",
    """eventId=({event_code}\d+)""",
    """externalId=({alert_id}\d+)""",
    """agt=({src_ip}[a-fA-F\d.:]+)\s""",
    """User:\s*([^\\]+\\*)?(SYSTEM|({user}[^\s]+))""",
    """Result\\*Description:\s*({outcome}[^\\]+)"""
  ]
}
cef-kaspersky-security-alert = {
  Vendor = Kaspersky
  Product = Kaspersky AV
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Fields = [
    """\Wdvc=({host}[a-fA-F\d.:]+)""",
    """\Wrt=({time}\d+)""",
    """\WdeviceNtDomain=(|({domain}.+?))(\s+\w+=|\s*$)""",
    """CEF:([^\|]*\|){5}({alert_name}[^\|]+)\|({alert_severity}[^\|]+)""",
    """\Wcat=(|({alert_type}.+?))(\s+\w+=|\s*$)""",
    """\Wdhost=(|({dest_host}.+?))(\s+\w+=|\s*$)""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]+)""",
    """\Wmsg=(|({additional_info}.+?))(\s+\w+=|\s*$)""",
   ]

```