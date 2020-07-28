#### Parser Content
```Java
{
Name = carbonblack-endpoint-process-file
  DataType = "file-activity"
  IsHVF = true
  Conditions = [ """filemod""" , """carbonblack""" , """sensor_action"""]
  Fields = ${CarbonBlackParserTemplates.carbonblack-endpoint.Fields} [
    ]
}
```