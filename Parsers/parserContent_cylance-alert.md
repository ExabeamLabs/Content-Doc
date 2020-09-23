#### Parser Content
```Java
{
Name = cylance-alert
  Vendor = Cylance
  Product = PROTECT
  Lms = QRadar
  DataType = "alert"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """Event Type: Threat""","""Is Running: ""","""Cylance Score: """]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """\[({host}[\w\-.]+)\]\s*Event Type:""",
    """Date: ({time}\d+\/\d+\/\d+ \d+:\d+:\d+ \w+)""",
    """File Name: ({malware_url}[^,]+)""",
    """Event Type:\s*({alert_type}[^,]+)""",
    """Event Name: ({alert_name}[^,]+)""",
    """Cylance Score: ({alert_severity}\d+)""",
    """Device Name: ({src_host}[^,]+)""",
    """IP Address: \(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """Path: ({process}[^,]+\\({process_name}[^,]+))""",
    """Threat Classification:\s*({alert_name}[^,]+),""",
    """Status:\s*({outcome}[^,]+),""",
    """MD5:\s*({md5}[^,]+),""",
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "src_host->malwareVictimHost", "alert_severity->sourceSeverity", "malware_url->malwareAttackerFile"]
    NameTemplate = """Cylance Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
    ]
  }
}
```