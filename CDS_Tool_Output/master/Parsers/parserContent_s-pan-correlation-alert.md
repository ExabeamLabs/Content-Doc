#### Parser Content
```Java
{
Name = s-pan-correlation-alert
  Vendor = Palo Alto Networks
  Product = WildFire
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "MM/dd/yy HH:mm:ss"
  Conditions = [ """,CORRELATION,"""]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """\d\d:\d\d:\d\d ({host}[\w\-.]+)""",
    """({time}\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """,CORRELATION,([^,]*,){6}(({domain}[^\\]+)\\)?({user}[^,]+)""",
    """,CORRELATION,([^,]*,){7}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """,CORRELATION,([^,]*,){8}({alert_type}[^,]+)""",
    """,CORRELATION,([^,]*,){10}({alert_name}[^,]+)""",
    """,CORRELATION,([^,]*,){11}({alert_severity}[^,]+)""",
    """,CORRELATION,([^,]*,){12}({additional_info}.+?)\s+$""",
    """\d\d:\d\d:\d\d,({alert_id}[^,]+)"""
    """Process Name: ({malware_url}[^,]+),"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_ip->malwareVictimHost", "alert_type->description", "malware_url->malwareAttackerUrl"]
    NameTemplate = """Palo Alto Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```