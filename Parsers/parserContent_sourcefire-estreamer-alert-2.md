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
	     """exabeam_time=({time}\d+-\d+-\d+ \d+:\d+:\d+)""",
	     """exabeam_host=({host}[\w.\-]+)""",
	     """Access Control Rule Name:\s*({alert_name}[^,]+)""",
	     """Application Protocol:\s*({alert_type}[^,]+)""",
	     """Access Control Rule Action:\s*({alert_severity}[^,]+)""",
	     """User:\s*(?:Unknown|({user}[^,]+))""",
	     """({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({src_port}\d+) -> ({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\:({dest_port}\d+)""",
	     """URL:\s*({malware_url}[^,]+)"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_ip->malwareVictimHost", "malware_url->malwareAttackerUrl", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Cisco Sourcefire Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```