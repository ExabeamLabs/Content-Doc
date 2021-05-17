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
    """\w+ \d\d \d\d:\d\d:\d\d ({host}[^\s]{1,2000})\s{0,100}Palo""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """User: (({domain}[^\\]{1,2000})\\)?({user}[^,]{1,2000})""",
    """from Computer: ({src_host}[^,]{1,2000})""",
    """eventID=({alert_name}[^\s]{1,2000}) \w+="""
    """Module Name: ({alert_type}[^,]{1,2000}),"""
    """sev=({alert_severity}\d{1,100})"""
    """Prevention Key: ({alert_id}[^\s]{1,2000}) \w+="""
    """Process Name: ({malware_url}[^,]{1,2000}),"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_host->malwareVictimHost", "alert_type->description", "malware_url->malwareAttackerUrl"]
    NameTemplate = """Palo Alto Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_host->host_name"]}
```