#### Parser Content
```Java
{
Name = json-mcafee-epo-alert-2
  Vendor = McAfee
  Product = McAfee Endpoint Security
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"name":"threatcategory"""", """"name":"threatname"""", """"name":"analyzername"""" ]
  Fields = [
    """"receivedutc":\{[^\}]{1,2000}?"value":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,3})?Z)"""",
    """"analyzerhostname":\{[^\}]{1,2000}?"value":"({host}[^"]{1,2000})"""",
    """"sourceipv6":\{[^\}]{1,2000}?"value":"\/?({src_ip}[a-fA-F\d:.]{1,2000})"""",
    """"sourceipv4":\{[^\}]{1,2000}?"value":"({src_ip}[a-fA-F\d:.]{1,2000})"""",
    """"threatseverity":\{[^\}]{1,2000}?"value":({alert_severity}\d{1,5})\}""",
    """"threatactiontaken":\{[^\}]{1,2000}?"value":"(none|({action}[^"]{1,2000}))"""",
    """"threatname":\{[^\}]{1,2000}?"value":"(\_|({alert_name}[^"]{1,2000}))"""",
    """"threattype":\{[^\}]{1,2000}?"value":"( |({alert_type}[^"]{1,2000}))"""",
    """"threateventid":\{[^\}]{1,2000}?"value":({alert_id}\d{1,20})""",
    """"threatcategory":\{[^\}]{1,2000}?"value":"({threat_category}[^"]{1,2000})"""",
    """"targetusername":\{[^\}]{1,2000}?"value":"((NT SERVICE|({domain}[^"\\]{1,2000}))\\{1,20})?({user}[^"]{1,2000})"""",
    """"sourceusername":\{[^\}]{1,2000}?"value":"((NT SERVICE|({domain}[^"\\]{1,2000}))\\{1,20})?({user}[^"]{1,2000})"""",
    """"targetprocessname":\{[^\}]{1,2000}?"value":"(null|({process}(({directory}[^"]{0,2000}?)\/+)?({process_name}[^"\/]{1,2000})))"""",    
    """"targethostname":\{[^\}]{1,2000}?"value":"({src_host}[^"]{1,2000})"""",
    """"analyzerdetectionmethod":\{[^\}]{1,2000}?"value":"({additional_info}[^"]{1,2000})"""",
    """"targetfilename":\{[^\}]{1,2000}?"value":"(?:|null|({malware_url}[^"]{1,2000}?[\\\/]?({malware_file_name}[^\\\/"]{1,2000}?)))""""
  ]
  DupFields = [ "directory->process_directory" ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "threat_category->malwareCategory", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_host->malwareVictimHost", "malware_file_name->malwareAttackerFile", "alert_type->malwareCategory", "action->description"]
    NameTemplate = """Mcafee Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name ="src_address", Fields=["src_host->host_name"]

}
```