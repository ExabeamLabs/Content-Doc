#### Parser Content
```Java
{
Name = cef-kaspersky-security-alert
  Conditions = [ """CEF:""", """|Kaspersky|Kaspersky Endpoint Security""" ]
  Fields = ${KasperskyParserTemplates.cef-kaspersky-security-alert.Fields}[
    """\WcategoryDeviceGroup=(|({alert_type}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """Action:\s{0,100}({action}[^\\]{1,2000})""",
    """fname=({file_path}({file_parent}[^=]{0,2000}?[\\\/]{1,2000})?({file_name}[^\\\/=]{1,2000}?(\.({file_ext}\w+))?))\s{1,100}\w+="""
    """requestClientApplication=({app}.+?)\s{0,100}\w+=""",
    """\Wdvchost=({src_host}[^\s]{1,2000})\s{1,100}\w+""",
    """eventId=({event_code}\d{1,100})""",
    """externalId=({alert_id}\d{1,100})""",
    """agt=({src_ip}[a-fA-F\d.:]{1,2000})\s""",
    """User:\s{0,100}([^\\]{1,2000}\\*)?(SYSTEM|({user}[^\s]{1,2000}))""",
    """Result\\*Description:\s{0,100}({outcome}[^\\]{1,2000})"""
  ]
}
cef-kaspersky-security-alert = {
  Vendor = Kaspersky
  Product = Kaspersky AV
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Fields = [
    """\Wdvc=({host}[a-fA-F\d.:]{1,2000})""",
    """\Wrt=({time}\d{1,100})""",
    """\WdeviceNtDomain=(|({domain}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """CEF:([^\|]{0,2000}\|){5}({alert_name}[^\|]{1,2000})\|({alert_severity}[^\|]{1,2000})""",
    """\Wcat=(|({alert_type}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdhost=(|({dest_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wmsg=(|({additional_info}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
   ]

```