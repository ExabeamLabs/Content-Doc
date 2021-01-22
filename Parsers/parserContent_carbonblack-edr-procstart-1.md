#### Parser Content
```Java
{
Name = carbonblack-edr-procstart-1
  DataType = "process-created"
  Conditions = [ """endpoint.event.procstart""", """"process_username":"""", """"EDR""" ]
  Fields = ${CarbonBlackParserTemplates.carbonblack-edr.Fields} [
    """"parent_path":"({parent_process}({parent_directory}[^"]+(\\|\/)+)?({parent_process_name}[^"]+))"""",
  ]
}
```