#### Parser Content
```Java
{
Name = lumension-failed-usb-activity-1
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """ READ-DENIED """, """ DeviceType="""", """ DeviceName="""" ]
  Fields = ${LumensionParserTemplates.lumension-usb-activity.Fields} [
    """scomc\s+(System|({process_name}.+?)) READ-DENIED \[""",
  ]
}
```