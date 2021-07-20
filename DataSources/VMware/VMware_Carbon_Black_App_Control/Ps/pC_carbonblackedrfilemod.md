#### Parser Content
```Java
{
Name = carbonblack-edr-filemod
  DataType = "file-write"
  Conditions = [ """CEF:""", """requestClientApplication=Carbon Black EDR""" , """endpoint.event.filemod""", """"process_username":"""" ]
  Fields = ${CarbonBlackParserTemplates.carbonblack-edr.Fields} [
  ]
}
```