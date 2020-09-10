#### Parser Content
```Java
{
Name = carbonblack-edr-crossproc
  DataType = "process-created"
  Conditions = [ """CEF:""", """requestClientApplication=Carbon Black EDR""" , """endpoint.event.crossproc""", """"process_username":"""" ]
  Fields = ${CarbonBlackParserTemplates.carbonblack-edr.Fields} [
  ]
}
```