#### Parser Content
```Java
{
Name = symantec-usb-read-1
  Conditions = [ """type":"""", ""","device":"""", """"action":"File Read"""" ]
  Fields = ${SymantecParserTemplates.symantec-usb-activity.Fields}[
     """device":"({device_id}[^"]+)""",
  ] 
}
```