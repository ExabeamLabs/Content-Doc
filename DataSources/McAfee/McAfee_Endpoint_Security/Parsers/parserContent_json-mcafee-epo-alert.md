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
    """"serverid\\*":\\*"({host}[^,"\\]+)""",
    """"threatseverity\\*":({alert_severity}[^,"]+)""",
    """"threatcategory\\*":\\*"({threat_category}[^,"\\]+)""",
    """"threatactiontaken\\*":\\*"({action}[^,"\\]+)""",
    """"sourceusername\\*":\\*"?((NT AUTHORITY|({domain}[^\\",]+))\\+)?(null|SYSTEM|({user}[^,"\\\s]+))""",
    """"targetusername\\*":(null|SYSTEM|({user}[^\\\s",]+))""",
    """"threatname\\*":\\*"(_|({alert_name}[^,"\\]+))\s*\\*"""",
    """"threattype\\*":\\*"(\s+|({alert_type}[^,"\\]+))""",
    """"targethostname\\*":\\*"({src_host}[^,"\\]+)""",
    """"targetfilename\\*":\\*"(?:|null|({malware_url}.*?[\\\/]?({malware_file_name}[^\\\/]+?)))\\*"""",
    """"analyzerdetectionmethod\\*":\\*"(\s+|({additional_info}[^,"\\]+))""",
    """"threateventid\\*":({alert_id}[^,"\\]+)""",
    """"targetprocessname\\*":\\*"(null|({process}(({directory}[^"]+?)\/+)?({process_name}[^"\/\\]*?)))\\*"""",
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