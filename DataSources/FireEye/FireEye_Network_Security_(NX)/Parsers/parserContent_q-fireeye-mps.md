#### Parser Content
```Java
{
Name = q-fireeye-mps
  Vendor = FireEye
  Product = FireEye Network Security (NX)
  Lms = QRadar
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = ["LEEF:", "FireEye|MPS"]
  Fields = [
    """devTime=({time}\w+ \d{1,100} \d{1,100} \d\d:\d\d:\d\d)""",
    """src=({src_ip}[^\^]+)\^""",
    """dst=({dest_ip}[^\^]+)\^""",
    """dvchost=({host}[^\^]+)\^""",
    """shost=({src_host}[^\^]+)\^""",
    """sname=({alert_name}[^\^]+)\^""",
    """FireEye\|MPS\|[^\|]+\|({alert_type}[^\|]+)\|sev=({alert_severity}[^\^]+)\^""",
    """externalId=({alert_id}[^\^]+)\^"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_id->sourceId", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_host->malwareVictimHost", "dest_ip->malwareAttackerIp"]
    NameTemplate = """FireEye Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```