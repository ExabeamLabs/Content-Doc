#### Parser Content
```Java
{
Name = win-disable-device-request
  DataType = "usb-activity"
  Conditions = [ """A request was made to disable a device.""" ]
  Fields = ${WinParserTemplates.d-xml-windows-device.Fields} [
    """({event_code}6419)""",
    """>({event_code}6419)<\/EventID>"""
    """({event_name}A request was made to disable a device.)"""
  ]
}
```