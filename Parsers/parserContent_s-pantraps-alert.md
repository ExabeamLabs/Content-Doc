#### Parser Content
```Java
{
Name = s-pantraps-alert
  Vendor = Palo Alto Networks
  Product = Traps
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Palo[Alto] TrapsAgent:""","""event from Computer:""","""Prevention Key:"""]
  Fields = [
    """\w+ \d\d \d\d:\d\d:\d\d ({host}[^\s]+)\s*Palo""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """User: (({domain}[^\\]+)\\)?({user}[^,]+)""",
    """from Computer: ({src_host}[^,]+)""",
    """eventID=({alert_name}[^\s]+) \w+="""
    """Module Name: ({alert_type}[^,]+),"""
    """sev=({alert_severity}\d+)"""
    """Prevention Key: ({alert_id}[^\s]+) \w+="""
    """Process Name: ({malware_url}[^,]+),"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_host->malwareVictimHost", "alert_type->description", "malware_url->malwareAttackerUrl"]
    NameTemplate = """Palo Alto Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_host->host_name"]}
```