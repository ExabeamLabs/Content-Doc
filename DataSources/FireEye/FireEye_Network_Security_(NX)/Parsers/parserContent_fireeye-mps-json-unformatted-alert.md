#### Parser Content
```Java
{
Name = fireeye-mps-json-unformatted-alert
  Vendor = FireEye
  Product = FireEye Network Security (NX)
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["msg: normal","product: ", " MPS","appliance-id:"]
  Fields = [
    """appliance: ({host}[^\s]+)""",
    """src:[\s\w:\-\.]+?ip:\s({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """src:[\s\w:\-\.]+?host:\s({src_host}[\w\-\.]+)""",
    """dst:[\s\w:\-\.]+?ip:\s({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """dst:[\s\w:\-\.]+?host:\s({dest_host}[\w\-\.]+)""",
    """alert\s\(id:({alert_id}\d{1,100})\,\s{1,100}?name:({alert_type}[^)]+)""",
    """malware\s\(name:({alert_name}[^)]+)""",
    """severity:\s({alert_severity}\w+)""",
    """occurred:\s({time}\d{4}-\d{2}-\d{2}( |T)\d{2}:\d{2}:\d{2}Z?)"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_id->sourceId", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_host->malwareVictimHost", "dest_ip->malwareAttackerIp"]
    NameTemplate = """FireEye Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```