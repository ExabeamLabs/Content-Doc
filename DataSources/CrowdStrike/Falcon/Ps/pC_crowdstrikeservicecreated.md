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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"timestamp":\s{0,100}"({time}\d{1,100})""",
    """"CommandLine":\s{0,100}"(|({process}({directory}(?:(\w+:)?[^:"]{1,2000}?)?[\\\/])?({process_name}[^"\\\s]{1,2000}?)))\s""",
    """"name":\s{0,100}"({service_name}[^"]{1,2000})""",
    """"event_simpleName":\s{0,100}"({event_name}[^"]{1,2000})""",
    """"UserName":\s{0,100}"({user}[^"\s]{1,2000})"""",
    """src-account-name":"({account_name}[^"]{1,2000})""",
  ]
  DupFields = [ "directory->process_directory" , "host->dest_host"]


}
```