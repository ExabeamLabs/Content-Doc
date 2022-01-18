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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"timestamp":"({time}\d{1,100})""",
    """"(ServiceImagePath|CommandLine)":"(|({process}({directory}(?:(\w+:)?[^:"]{1,2000}?)?[\\\/])?({process_name}[^"\\\s]{1,2000}?)))\s""",
    """"ServiceDisplayName":"({service_name}[^"]{1,2000})""",
    """"UserName":"({user}[^"\s]{1,2000})"""",
    """"ServiceDescription":"({additional_info}[^"]{1,2000})"""
    """"aid":"({aid}[^"]{1,2000})"""
  ]
  DupFields = [ "directory->process_directory" ]


}
```