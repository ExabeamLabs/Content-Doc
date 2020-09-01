#### Parser Content
```Java
{
Name = carbonblack-edr-netconn
  DataType = "network-connection"
  Conditions = [ """CEF:""", """requestClientApplication=Carbon Black EDR""" , """endpoint.event.netconn""", """"process_username":"""" ]
  Fields = ${CarbonBlackParserTemplates.carbonblack-edr.Fields} [
  ]
}
```