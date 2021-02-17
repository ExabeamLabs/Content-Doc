#### Parser Content
```Java
{
Name = symantec-usb-write-2
  Conditions = [ """type":"""", ""","device":"""", """"action":"File Write"""" ]
  Fields = ${SymantecParserTemplates.symantec-usb-activity.Fields}[
     """device":"({device_id}[^"]+)""",
  ]
}
```