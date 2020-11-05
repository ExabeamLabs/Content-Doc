#### Parser Content
```Java
{
Name = cc-carbonblack-edr-netconn
  DataType = "network-connection"
  Conditions = [ """CEF:""", """|Skyformation|""", """requestClientApplication=""" , """"type":"endpoint.event.netconn"""", """destinationServiceName=""", """"process_username":"""" ]
  Fields = ${CarbonBlackParserTemplates.carbonblack-edr.Fields} [
    """"parent_path":"({parent_process}({parent_directory}[^"]+(\\|\/)+)?({parent_process_name}[^"]+))"""",
  ]
}
```