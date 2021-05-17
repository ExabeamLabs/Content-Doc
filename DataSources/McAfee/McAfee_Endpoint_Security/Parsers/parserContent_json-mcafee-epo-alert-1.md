#### Parser Content
```Java
{
Name = json-mcafee-epo-alert-1
  Vendor = McAfee
  Product = McAfee Endpoint Security
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"analyzername":"""", """"threatcategory":"av.detect"""", """"mccomputername":"""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"generatedtime":"({time}[^"]{1,2000})"""",
    """"targetusername":"(({domain}[^"\\]{1,2000})\\+)?({user}[^"\\\s]{1,2000})"""",
    """"domainname":"({domain}[^"]{1,2000})"""",
    """"ipaddress":"({src_ip}[^"]{1,2000})"""",
    """"threatcategory":"({threat_category}[^"]{1,2000})"""",
    """"sourceprocessname":"({process}(({directory}[^"]{1,2000}?)\\+)?({process_name}[^"\\]{0,2000}))"""",
    """"operatingsystem":"({os}[^"]{1,2000})"""",
    """"analyzerdetectionmethod":"(\s{1,100}|({additional_info}[^"]{1,2000}))"""",
    """"action":"(_|({alert_name}[^"]{1,2000}))"""",
    """"autoid":({alert_id}[^",]{1,2000})""",
    """"targetfilename":"({malware_url}.*?[\\\/]?({malware_file_name}[^\\\/]{1,2000}?))"""",
    """"analyzername":"({event_name}[^"]{1,2000})"""",
    """"threattype":"(\s{1,100}|({alert_type}[^"]{1,2000}))"""",
    """"mccomputername":"({src_host}[^"]{1,2000})"""",
  ]
  DupFields = [ "directory->process_directory" ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "threat_category->malwareCategory", "alert_id->sourceId", "src_host->malwareVictimHost", "malware_file_name->malwareAttackerFile", "alert_type->malwareCategory", "malware_url->malwareAttackerUrl"]
    NameTemplate = """Mcafee Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```