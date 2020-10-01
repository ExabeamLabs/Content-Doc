#### Parser Content
```Java
{
Name = crowdstrike-service-created
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Direct
  DataType = "process-created"
  TimeFormat = "epoch"
  Conditions = [ """"event_simpleName":""", """"ServiceStarted"""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """"timestamp":\s*"({time}\d+)""",
    """"CommandLine":\s*"(|({process}({directory}(?:(\w+:)?[^:"]+?)?[\\\/])?({process_name}[^"\\\s]+?)))\s""",
    """"name":\s*"({service_name}[^"]+)""",
    """"event_simpleName":\s*"({event_name}[^"]+)""",
    """"UserName":\s*"({user}[^"\s]+)"""",
  ]
  DupFields = [ "directory->process_directory" , "host->dest_host"]
}
```