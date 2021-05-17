#### Parser Content
```Java
{
Name = json-mcafee-epo-alert
  Vendor = McAfee
  Product = McAfee Endpoint Security
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"analyzername""", """"threatcategory""" ]
  Fields = [
    """"receivedutc\\*":\\*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"serverid\\*":\\*"({host}[^,"\\]{1,2000})""",
    """"threatseverity\\*":({alert_severity}[^,"]{1,2000})""",
    """"threatcategory\\*":\\*"({threat_category}[^,"\\]{1,2000})""",
    """"threatactiontaken\\*":\\*"({action}[^,"\\]{1,2000})""",
    """"sourceusername\\*":\\*"?((NT AUTHORITY|({domain}[^\\",]{1,2000}))\\+)?(null|SYSTEM|({user}[^,"\\\s]{1,2000}))""",
    """"targetusername\\*":(null|SYSTEM|({user}[^\\\s",]{1,2000}))""",
    """"threatname\\*":\\*"(_|({alert_name}[^,"\\]{1,2000}))\s{0,100}\\*"""",
    """"threattype\\*":\\*"(\s{1,100}|({alert_type}[^,"\\]{1,2000}))""",
    """"targethostname\\*":\\*"({src_host}[^,"\\]{1,2000})""",
    """"targetfilename\\*":\\*"(?:|null|({malware_url}.*?[\\\/]?({malware_file_name}[^\\\/]{1,2000}?)))\\*"""",
    """"analyzerdetectionmethod\\*":\\*"(\s{1,100}|({additional_info}[^,"\\]{1,2000}))""",
    """"threateventid\\*":({alert_id}[^,"\\]{1,2000})""",
    """"targetprocessname\\*":\\*"(null|({process}(({directory}[^"]{1,2000}?)\/+)?({process_name}[^"\/\\]{0,2000}?)))\\*"""",
  ]
  DupFields = [ "directory->process_directory" ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "threat_category->malwareCategory", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_host->malwareVictimHost", "malware_file_name->malwareAttackerFile", "alert_type->malwareCategory", "action->description"]
    NameTemplate = """Mcafee Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_host->host_name"]}
```