#### Parser Content
```Java
{
Name = symantec-epp-cef-alert-2
  Conditions = ["""|Symantec|Endpoint Protection|""", """|Intrusion Detected"""]
  Fields = ${SymantecParserTemplates.symantec-epp-cef-alert-1.Fields} [
    """\|Symantec\|Endpoint Protection\|([^|]*?\|){2}({alert_name}[^|]+?)\|""",
    """\smsg=({additional_info}[^=]+?)\s+\w+=""",
    """\sact=({outcome}[^\s]+)""",
  ]
  SOAR {
    IncidentType = "malware"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_host->malwareVictimHost", "alert_type->description"]
      NameTemplate = """Symantec Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```