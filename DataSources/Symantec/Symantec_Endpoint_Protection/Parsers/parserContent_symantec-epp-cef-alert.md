#### Parser Content
```Java
{
Name = symantec-epp-cef-alert
  Conditions = ["""|Symantec|Endpoint Protection|"""]
  Fields = ${SymantecParserTemplates.symantec-epp-cef-alert-1.Fields} [
    """\scatdt=({category}[^=]+?)\s+(\w+=|$)""",
    """\scs6=({category}[^=]+?)\s+(\w+=|$)""",
    """\scn1=({viruses_num}\d+)""",
  ]
  SOAR {
    IncidentType = "malware"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_host->malwareVictimHost", "alert_type->description", "malware_url->malwareAttackerUrl"]
      NameTemplate = """Symantec Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```