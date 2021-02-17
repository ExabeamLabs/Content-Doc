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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"generatedtime":"({time}[^"]+)"""",
    """"targetusername":"(({domain}[^"\\]+)\\+)?({user}[^"\\\s]+)"""",
    """"domainname":"({domain}[^"]+)"""",
    """"ipaddress":"({src_ip}[^"]+)"""",
    """"threatcategory":"({threat_category}[^"]+)"""",
    """"sourceprocessname":"({process}(({directory}[^"]+?)\\+)?({process_name}[^"\\]*))"""",
    """"operatingsystem":"({os}[^"]+)"""",
    """"analyzerdetectionmethod":"(\s+|({additional_info}[^"]+))"""",
    """"action":"(_|({alert_name}[^"]+))"""",
    """"autoid":({alert_id}[^",]+)""",
    """"targetfilename":"({malware_url}.*?[\\\/]?({malware_file_name}[^\\\/]+?))"""",
    """"analyzername":"({event_name}[^"]+)"""",
    """"threattype":"(\s+|({alert_type}[^"]+))"""",
    """"mccomputername":"({src_host}[^"]+)"""",
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