#### Parser Content
```Java
{
Name = cef-sentinelone-security-alert-6
  Vendor = SentinelOne
  Product = Singularity 
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """"classification":"""", """"threatName":"""", """"mitigationStatus":""", """"engines":"""]
  Fields = [
     """exabeam_host=(::ffff:)?({host}[^\s]{1,2000})""",
     """"createdAt":\s{0,100}"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)""",
     """"updatedAt":\s{0,100}"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)""",
     """"classification":\s{0,100}"({alert_name}({alert_type}[^"]{1,2000}))""",
     """"title":\s{0,100}"({alert_name}[^"]{1,2000})""",
     """"agentIp(V4|V6)?":\s{0,100}"(::ffff:)?({src_ip}[\da-fA-f\.:]{1,2000})"""",
     """"fileDisplayName":\s{0,100}"({file_name}[^"]{1,2000})""",
     """"filePath":\s{0,100}"({malware_url}[^"]{1,2000})""",
     """"agentDomain":\s{0,100}"(unknown|({src_domain}[^"]{1,2000}))""",
     """"agentComputerName":\s{0,100}"({src_host}[^"]{1,2000})""",
     """"fileExtensionType":(\s{0,100}"None|null|\s{0,100}"{1,20}(Unknown|({file_type}[^"]{1,2000}))")""",
     """"agentLastLoggedInUserName":"({last_loggedin_user}[^"]{1,2000})"""",
     """"processUser":"(({process_domain}[^\\"]{1,2000})\\{1,200})?({process_user}[^"]{1,2000})",""",
     """username":"(({domain}[^\\"]{1,2000})\\{1,200})?({user}[^"]{1,2000})",""",
     """"rank":({alert_severity}\d{1,100})""",
     """"mitigationReport":({additional_info}\{.{1,400}?\}\}),""",
     """"fileContentHash":"({md5}[^"]{1,2000})"""",
     """"id":"({alert_id}\d{1,2000})"""",
     """"action":"quarantine".{0,2000}?"status":"({quarantine_status}\w{1,2000})"""",
     """"action":"kill".{0,2000}?"status":"({kill_status}\w{1,2000})"""",
     """"mitigationStatus":"({outcome}[^"]{1,2000})"""",
     """"threatId":"({alert_id}\d{1,2000})"""",
     """"mitigationMode":"({mitigation_mode}[^"]{1,2000})"""",
     """"agentMachineType":"({host_type}[^"]{1,2000})"""",
     """"agentOsType":"({os}[^"]{1,2000})"""",
     """"incidentStatus":"({incident_status}[^"]{1,2000})"""",
     """"analystVerdict":"({verdict}[^"]{1,2000})"""",
     """"groupName":"({group_name}[^"]{1,2000})""""
  ]
   SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "src_host->malwareVictimHost", "alert_type->description", "malware_url->malwareAttackerUrl","file_name->malwareAttackerFile"]
    NameTemplate = """SentinelOne Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name ="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]

}
```