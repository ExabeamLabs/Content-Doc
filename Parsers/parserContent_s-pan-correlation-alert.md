#### Parser Content
```Java
{
Name = s-pan-correlation-alert
  Vendor = Palo Alto Networks
  Product = WildFire
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,CORRELATION,"""]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """\d\d:\d\d:\d\d ({host}[\w\-.]+)""",
    """,CORRELATION,.+?({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """,CORRELATION,([^,]*,){4}(|(({domain}[^\\]+)\\)?({user}[^,]+)),""",
    """,CORRELATION,([^,]*,){3}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """,CORRELATION,([^,]*,){15}({alert_type}[^,]+)""",
    """,CORRELATION,([^,]*,){6}({alert_name}[^,]+)""",
    """,CORRELATION,([^,]*,){7}({alert_severity}[^,]+)""",
    """,CORRELATION,([^,]*,){17}\\?"*({additional_info}[^\.]+?)\.""",
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