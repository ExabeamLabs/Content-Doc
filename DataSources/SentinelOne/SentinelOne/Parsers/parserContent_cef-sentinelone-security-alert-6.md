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
     """"createdAt":\s*"({time}\d+-\d+-\d+T\d+:\d+:\d+\.\d+Z)""",
     """"classification":\s*"({alert_name}[^"]+)""",
     """"agentIp":\s*"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
     """"fileDisplayName":\s*"({file_name}[^"]+)""",
     """"filePath":\s*"({malware_url}[^"]+)""",
     """"agentDomain":\s*"(unknown|({src_domain}[^"]+))""",
     """"agentComputerName":\s*"({src_host}[^"]+)""",
     """"fileExtensionType":(\s*"None|null|\s*"+(Unknown|({file_type}[^"]+))")""",
     """username":"((NT AUTHORITY|({domain}[^\\"]+))\\+)?(SYSTEM|({user}[^"]+))",""",
     """"rank":({alert_severity}\d+)""",
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