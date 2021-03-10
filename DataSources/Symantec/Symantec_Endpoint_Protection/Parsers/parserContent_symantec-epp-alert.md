#### Parser Content
```Java
{
Name = symantec-epp-alert
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """,Actual action:""",""",Requested action:""" ]
  Fields = [
         """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
         """exabeam_host=({host}\S+)""",
         """Computer name:\s*(?:0+|({host}[^,]+))""",
         """Event time:\s*({time}[\d\- :]+)""",
         """({alert_type}Virus found)""",
         """SymantecServer:\s*({alert_type}[^,]+)""",
         """SymantecServer:\s*({alert_severity}[^,]+)""",
         """IP Address:\s*({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
         """Risk name:\s*({alert_name}[^,]+)""",
         """\d\d:\d\d:\d\d,\s*({alert_severity}Minor|Info|Critical|Major|Security risk found|Virus found)""",
         """Risk Level:\s*({alert_severity}[^,]+)""",
         """Occurrences:\s*\d+,({malware_url}[^,]+)""",
         """User(\s+Name)?:\s*(SYSTEM|({user}[^,]+))""",
         """Computer name:\s*(?:0+|({src_host}[^,]+))""",
         """Source computer:\s*(?:0+|({dest_host}[^,]+))?,""",
         """Source IP:\s*({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
         """Confidence:\s*({additional_info}[^,]+)""",
         """Actual action:\s*({outcome}[^,]+)""",
         """Application hash:\s*(|({file_hash}[^,]+)),""",
         """Hash type:\s*(|({hash_type}[^,]+)),"""
	]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "src_host->malwareVictimHost", "malware_url->malwareAttackerFile", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Symantec Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```