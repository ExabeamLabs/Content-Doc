#### Parser Content
```Java
{
Name = carbonblack-endpoint-process-start
  DataType = "process-created"
  IsHVF = true
  Conditions = [ """procstart""" , """carbonblack""" , """sensor_action""" ]
  Fields = ${CarbonBlackParserTemplates.carbonblack-endpoint.Fields} [
    ]
}
```