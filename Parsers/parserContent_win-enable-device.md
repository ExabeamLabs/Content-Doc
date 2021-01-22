#### Parser Content
```Java
{
Name = win-enable-device
  DataType = "usb-insert"
  Conditions = [ """A device was enabled.""", """>6422</EventID>""" ]
  Fields = ${WinParserTemplates.d-xml-windows-device.Fields} [
    """>({event_code}6422)<\/EventID>"""
    """({event_name}A device was enabled.)"""
  ]
}
```