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
         """Computer name:\s{0,100}(?:0+|({host}[^,]{1,2000}))""",
         """Event time:\s{0,100}({time}[\d\- :]{1,2000})""",
         """({alert_type}Virus found)""",
         """IP Address:\s{0,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
         """Risk name:\s{0,100}({alert_name}[^,]{1,2000})""",
         """\d\d:\d\d:\d\d,\s{0,100}({alert_severity}Minor|Info|Critical|Major|Security risk found|Virus found)""",
         """Sensitivity:\s({alert_severity}[^,]{1,2000})""",
         """Risk Level:\s{0,100}({alert_severity}[^,]{1,2000})""",
         """Occurrences:\s{0,100}\d{1,100},(File path:\s{1,100})?({malware_url}[^,]{1,2000})""",
         """User\s{0,100}(Name)?:\s{0,100}(SYSTEM,|({user}[^,]{1,2000}))""",
         """Computer name:\s{0,100}(?:0+|({src_host}[^,]{1,2000}))""",
         """Source computer:\s{0,100}(?:0+|({dest_host}[^,]{1,2000}))?,""",
         """Source IP:\s{0,100}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
         """Confidence:\s{0,100}({additional_info}[^,]{1,2000})""",
         """Actual action:\s{0,100}({outcome}[^,]{1,2000})""",
         """Application hash:\s{0,100}(|({file_hash}[^,]{1,2000})),""",
         """Hash type:\s{0,100}(|({hash_type}[^,]{1,2000})),""",
         """Application name:\s"{0,20}({process_name}[^",]{1,2000})""", 
	]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "src_host->malwareVictimHost", "malware_url->malwareAttackerFile", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Symantec Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```