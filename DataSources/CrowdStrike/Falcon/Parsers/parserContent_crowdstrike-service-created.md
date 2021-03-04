#### Parser Content
```Java
{
Name = crowdstrike-service-created
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Direct
  DataType = "process-created"
  TimeFormat = "epoch"
  Conditions = [ """"event_simpleName":"ServiceStarted"""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """"timestamp":"({time}\d+)""",
    """"CommandLine":"(|({process}({directory}(?:(\w+:)?[^:"]+?)?[\\\/])?({process_name}[^"\\\s]+?)))\s""",
    """"name":"({service_name}[^"]+)""",
    """"event_simpleName":"({event_name}[^"]+)""",
    """"UserName":"({user}[^"\s]+)"""",
  ]
  DupFields = [ "directory->process_directory" ]
}
```