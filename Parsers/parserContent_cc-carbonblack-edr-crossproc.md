#### Parser Content
```Java
{
Name = cc-carbonblack-edr-crossproc
  DataType = "process-created"
  Conditions = [ """CEF:""", """|Skyformation|""", """requestClientApplication=""" , """"type":"endpoint.event.crossproc"""", """destinationServiceName=""", """"process_username":"""" ]
  Fields = ${CarbonBlackParserTemplates.carbonblack-edr.Fields} [
    """"parent_path":"({parent_process}({parent_directory}[^"]+(\\|\/)+)?({parent_process_name}[^"]+))"""",
  ]
}
```