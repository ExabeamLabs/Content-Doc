#### Parser Content
```Java
{
Name = win-disable-device
  DataType = "usb-activity"
  Conditions = [ """A device was disabled.""" ]
  Fields = ${WinParserTemplates.d-xml-windows-device.Fields} [
    """({event_code}6420)""",
    """>({event_code}6420)<\/EventID>"""
    """({event_name}A device was disabled.)"""
  ]
}
```