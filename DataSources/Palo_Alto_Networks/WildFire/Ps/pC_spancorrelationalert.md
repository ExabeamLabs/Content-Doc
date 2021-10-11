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
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """\d\d:\d\d:\d\d ({host}[\w\-.]{1,2000})""",
    """,CORRELATION,([^,]{0,2000},){2}({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """,CORRELATION,([^,]{0,2000},){4}(|(({domain}[^\\]{1,2000})\\)?({user}[^,]{1,2000})),""",
    """,CORRELATION,([^,]{0,2000},){3}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """,CORRELATION,([^,]{0,2000},){15}({alert_name}[^,]{1,2000})""",
    """,CORRELATION,([^,]{0,2000},){6}({alert_type}[^,]{1,2000})""",
    """,CORRELATION,([^,]{0,2000},){7}({alert_severity}[^,]{1,2000})""",
    """,CORRELATION,([^,]{0,2000},){17}\\?"{0,20}({additional_info}[^\.]{1,2000}?)\.""",
    """\d\d:\d\d:\d\d,({alert_id}[^,]{1,2000}),""",
    """Process Name: ({malware_url}[^,]{1,2000}),"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_ip->malwareVictimHost", "alert_type->description", "malware_url->malwareAttackerUrl"]
    NameTemplate = """Palo Alto Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```