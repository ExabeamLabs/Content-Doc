#### Parser Content
```Java
{
Name = sourcefire-estreamer-alert-2
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Access Control Rule Name:""","""[Primary Detection Engine""" ]
  Fields = [
	     """exabeam_time=({time}\d{1,100}-\d{1,100}-\d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
	     """exabeam_host=({host}[\w.\-]{1,2000})""",
	     """Access Control Rule Name:\s{0,100}({alert_name}[^,]{1,2000})""",
	     """Application Protocol:\s{0,100}({alert_type}[^,]{1,2000})""",
	     """Access Control Rule Action:\s{0,100}({alert_severity}[^,]{1,2000})""",
	     """User:\s{0,100}(?:Unknown|({user}[^,]{1,2000}))""",
	     """({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({src_port}\d{1,100}) -> ({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\:({dest_port}\d{1,100})""",
	     """URL:\s{0,100}({malware_url}[^,]{1,2000})""",
  	     """Web App:\s(Unknown|({process_name}[^,]{1,2000}))""",
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_ip->malwareVictimHost", "malware_url->malwareAttackerUrl", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Cisco Sourcefire Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name ="src_address", Fields=["src_ip->ip_address"]

}
```