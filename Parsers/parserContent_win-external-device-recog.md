#### Parser Content
```Java
{
Name = win-external-device-recog
  DataType = "usb-insert"
  Conditions = [ """A new external device was recognized by the system.""" ]
  Fields = ${WinParserTemplates.d-xml-windows-device.Fields} [
    """({event_code}6416)""",
    """>({event_code}6416)<\/EventID>""",
    """({event_name}A new external device was recognized by the system.)"""
  ]
  DupFields = [ "event_name->activity" ]
}
```