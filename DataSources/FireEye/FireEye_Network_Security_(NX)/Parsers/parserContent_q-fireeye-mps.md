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
    """src=({src_ip}[^\^]{1,2000})\^""",
    """dst=({dest_ip}[^\^]{1,2000})\^""",
    """dvchost=({host}[^\^]{1,2000})\^""",
    """shost=({src_host}[^\^]{1,2000})\^""",
    """sname=({alert_name}[^\^]{1,2000})\^""",
    """FireEye\|MPS\|[^\|]{1,2000}\|({alert_type}[^\|]{1,2000})\|sev=({alert_severity}[^\^]{1,2000})\^""",
    """externalId=({alert_id}[^\^]{1,2000})\^"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_id->sourceId", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_host->malwareVictimHost", "dest_ip->malwareAttackerIp"]
    NameTemplate = """FireEye Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```