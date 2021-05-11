#### Parser Content
```Java
{
Name = cef-kaspersky-security-alert
  Conditions = [ """CEF:""", """|Kaspersky|Kaspersky Endpoint Security""" ]
  Fields = ${KasperskyParserTemplates.cef-kaspersky-security-alert.Fields}[
    """\WcategoryDeviceGroup=(|({alert_type}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """Action:\s{0,100}({action}[^\\]+)""",
    """fname=({file_path}({file_parent}[^=]*?[\\\/]+)?({file_name}[^\\\/=]+?(\.({file_ext}\w+))?))\s{1,100}\w+="""
    """requestClientApplication=({app}.+?)\s{0,100}\w+=""",
    """\Wdvchost=({src_host}[^\s]+)\s{1,100}\w+""",
    """eventId=({event_code}\d{1,100})""",
    """externalId=({alert_id}\d{1,100})""",
    """agt=({src_ip}[a-fA-F\d.:]+)\s""",
    """User:\s{0,100}([^\\]+\\*)?(SYSTEM|({user}[^\s]+))""",
    """Result\\*Description:\s{0,100}({outcome}[^\\]+)"""
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
    """\Wrt=({time}\d{1,100})""",
    """\WdeviceNtDomain=(|({domain}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """CEF:([^\|]*\|){5}({alert_name}[^\|]+)\|({alert_severity}[^\|]+)""",
    """\Wcat=(|({alert_type}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdhost=(|({dest_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]+)""",
    """\Wmsg=(|({additional_info}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
   ]

```