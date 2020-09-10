#### Parser Content
```Java
{
Name = carbonblack-edr-procstart
  DataType = "process-created"
  Conditions = [ """CEF:""", """requestClientApplication=Carbon Black EDR""" , """endpoint.event.procstart""", """"process_username":"""" ]
  Fields = ${CarbonBlackParserTemplates.carbonblack-edr.Fields} [
  ]
}
```