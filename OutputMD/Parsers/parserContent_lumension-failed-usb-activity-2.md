#### Parser Content
```Java
{
Name = lumension-failed-usb-activity-2
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """ WRITE-DENIED """, """ DeviceType="""", """ DeviceName="""" ]
  Fields = ${LumensionParserTemplates.lumension-usb-activity.Fields} [
    """scomc\s+(System|({process_name}.+?)) WRITE-DENIED \[""",
  ]
}
```