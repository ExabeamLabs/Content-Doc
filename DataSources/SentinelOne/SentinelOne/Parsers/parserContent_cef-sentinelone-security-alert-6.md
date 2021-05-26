#### Parser Content
```Java
{
Name = cef-sentinelone-security-alert-6
  Vendor = SentinelOne
  Product = SentinelOne
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """"classification":"Malware"""", """mitigationReport""", """threatName""", """mitigationStatus""", """maliciousGroupId"""]
  Fields = [
     """exabeam_host=({host}[^\s]{1,2000})""",
     """"createdAt":\s{0,100}"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)""",
     """"classification":\s{0,100}"({alert_name}[^"]{1,2000})""",
     """"agentIp":\s{0,100}"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
     """"fileDisplayName":\s{0,100}"({file_name}[^"]{1,2000})""",
     """"filePath":\s{0,100}"({malware_url}[^"]{1,2000})""",
     """"agentDomain":\s{0,100}"(unknown|({src_domain}[^"]{1,2000}))""",
     """"agentComputerName":\s{0,100}"({src_host}[^"]{1,2000})""",
     """"fileExtensionType":(\s{0,100}"None|null|\s{0,100}"{1,20}(Unknown|({file_type}[^"]{1,2000}))")""",
     """username":"((NT AUTHORITY|({domain}[^\\"]{1,2000}))\\+)?(SYSTEM|({user}[^"]{1,2000}))",""",
     """"rank":({alert_severity}\d{1,100})""",
     """"mitigationReport":\{"({outcome}[^"]{1,2000})"""",
     """"fileContentHash":"({md5}[^"]{1,2000})"""",
  ]
   SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "src_host->malwareVictimHost", "alert_type->description", "malware_url->malwareAttackerUrl","file_name->malwareAttackerFile"]
    NameTemplate = """SentinelOne Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```