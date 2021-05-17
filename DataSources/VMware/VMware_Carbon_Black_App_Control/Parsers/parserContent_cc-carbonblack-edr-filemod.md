#### Parser Content
```Java
{
Name = cc-carbonblack-edr-filemod
  DataType = "file-write"
  Conditions = [ """CEF:""", """|Skyformation|""", """requestClientApplication=""", """"type":"endpoint.event.filemod"""", """destinationServiceName=""", """"process_username":"""" ]
  Fields = ${CarbonBlackParserTemplates.carbonblack-edr.Fields} [
    """"parent_path":"({parent_process}({parent_directory}[^"]{1,2000}(\\|\/)+)?({parent_process_name}[^"]{1,2000}))"""",
  ]
}
```