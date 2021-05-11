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
    """"timestamp":\s{0,100}"({time}\d{1,100})""",
    """"CommandLine":\s{0,100}"(|({process}({directory}(?:(\w+:)?[^:"]+?)?[\\\/])?({process_name}[^"\\\s]+?)))\s""",
    """"name":\s{0,100}"({service_name}[^"]+)""",
    """"event_simpleName":\s{0,100}"({event_name}[^"]+)""",
    """"UserName":\s{0,100}"({user}[^"\s]+)"""",
    """src-account-name":"({account_name}[^"]+)""",
  ]
  DupFields = [ "directory->process_directory" , "host->dest_host"]
}
```