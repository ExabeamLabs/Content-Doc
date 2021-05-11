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
     """exabeam_host=({host}[^\s]+)""",
     """"createdAt":\s{0,100}"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)""",
     """"classification":\s{0,100}"({alert_name}[^"]+)""",
     """"agentIp":\s{0,100}"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
     """"fileDisplayName":\s{0,100}"({file_name}[^"]+)""",
     """"filePath":\s{0,100}"({malware_url}[^"]+)""",
     """"agentDomain":\s{0,100}"(unknown|({src_domain}[^"]+))""",
     """"agentComputerName":\s{0,100}"({src_host}[^"]+)""",
     """"fileExtensionType":(\s{0,100}"None|null|\s{0,100}"{1,20}(Unknown|({file_type}[^"]+))")""",
     """username":"((NT AUTHORITY|({domain}[^\\"]+))\\+)?(SYSTEM|({user}[^"]+))",""",
     """"rank":({alert_severity}\d{1,100})""",
     """"mitigationReport":\{"({outcome}[^"]+)"""",
     """"fileContentHash":"({md5}[^"]+)"""",
  ]
   SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "src_host->malwareVictimHost", "alert_type->description", "malware_url->malwareAttackerUrl","file_name->malwareAttackerFile"]
    NameTemplate = """SentinelOne Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```