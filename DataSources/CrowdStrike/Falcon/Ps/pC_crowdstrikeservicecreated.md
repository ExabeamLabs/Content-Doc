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
    """exabeam_host=(gcs-topic|({host}[^\s]{1,2000}))""",
    """"timestamp":\s{0,100}"({time}\d{1,100})"""",
    """"CommandLine":\s{0,100}"({command_line}.+?)\s{0,100}","TargetProcessId""",
    """"name":\s{0,100}"({service_name}[^"]{1,2000})""",
    """"ServiceDisplayName":"({service_name}[^"]{1,2000})"""",
    """"event_simpleName":\s{0,100}"({event_code}[^"]{1,2000})""",
    """"UserName":\s{0,100}"((LOCAL SERVICE|({user_fullname}({user_firstname}[^\s"]{1,2000})\s({user_lastname}[^"]{1,2000})))|({user}[^"\s]{1,2000}))"""",
    """src-account-name":"({account_name}[^"]{1,2000})""",
    """"ImageFileName":\s{0,100}"[\\\?]{1,200}(|({process}({directory}[^"]{0,2000}?)(\\+({process_name}[^"\\]{1,2000}?))?))""""
  ]
  DupFields = [ "directory->process_directory" , "host->dest_host"]


}
```