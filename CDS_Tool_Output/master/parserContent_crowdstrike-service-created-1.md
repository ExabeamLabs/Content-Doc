#### Parser Content
```Java
{
Name = crowdstrike-service-created-1
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Direct
  DataType = "process-created"
  TimeFormat = "epoch"
  Conditions = [ """"event_simpleName":"CreateService"""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """"timestamp":"({time}\d+)""",
    """"(ServiceImagePath|CommandLine)":"(|({process}({directory}(?:(\w+:)?[^:"]+?)?[\\\/])?({process_name}[^"\\\s]+?)))\s""",
    """"ServiceDisplayName":"({service_name}[^"]+)""",
    """"UserName":"({user}[^"\s]+)"""",
    """"ServiceDescription":"({additional_info}[^"]+)"""
  ]
  DupFields = [ "directory->process_directory" ]
}
```