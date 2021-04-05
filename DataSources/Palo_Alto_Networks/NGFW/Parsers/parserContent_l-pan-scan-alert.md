#### Parser Content
```Java
{
Name = l-pan-scan-alert
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,THREAT,scan,""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """THREAT,([^,]*,){27}(("[^"]*")|[^,]*),([^,]*,){27}({host}[\w\-\.]+)(,|$)""",
    """:\d\d:\d\d\s+({host}[\w.-]+)\s""",
    """({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d),[^,]*,THREAT,({alert_type}[^,]+),([^,]*,){2}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),""",
    """,THREAT,([^,]*,){9}(({domain}[^\\,]+)\\+)?({user}[^\\,]+)""",
    """,THREAT,([^,]*,){8}(({domain}[^\\,]+)\\+)?({user}[^\\,]+)""",
    """,THREAT,([^,]*,){27}"?({malware_url}[^,"]+)""",
    """,THREAT,([^,]*,){27}(("[^"]*")|[^,]*),({alert_name}[^,]+),""",
    """,THREAT,([^,]*,){27}(("[^"]*")|[^,]*),([^,]*,){2}({alert_severity}[^,]+),""",
    """,THREAT,([^,]*,){27}(("[^"]*")|[^,]*),([^,]*,){4}({alert_id}\d+)""",
    """,THREAT,([^,]*,){20}(?:|({src_port}\d+)),(?:|({dest_port}\d+)),(?:[^,]*,){3}(?:|({protocol}[^,]+)),(?:|({action}[^,]*)),"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_ip->malwareVictimHost", "alert_type->malwareCategory", "malware_url->malwareAttackerUrl", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Palo Alto Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```