#### Parser Content
```Java
{
Name = cc-carbonblack-edr-procstart
  DataType = "process-created"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSSSSS"
  Conditions = [ """CEF:""", """|Skyformation|""", """requestClientApplication=""" , """"type":"endpoint.event.procstart"""", """destinationServiceName=""", """"process_username":"""" ]
  Fields = ${CarbonBlackParserTemplates.carbonblack-edr.Fields} [
    """"device_timestamp"{1,20}:"{1,20}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{7})""",
    """"parent_path":"({parent_process}({parent_directory}[^"]{1,2000}(\\|\/)+)?({parent_process_name}[^"]{1,2000}))"""",
  ]
  DupFields = ["activity_type->event_name"]
}
```