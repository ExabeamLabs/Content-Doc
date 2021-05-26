#### Parser Content
```Java
{
Name = cylance-alert
  Vendor = BlackBerry
  Product = BlackBerry Protect
  Lms = QRadar
  DataType = "alert"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """Event Type: Threat""","""Is Running: ""","""Cylance Score: """]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\[({host}[\w\-.]{1,2000})\]\s{0,100}Event Type:""",
    """Date: ({time}\d{1,100}\/\d{1,100}\/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \w+)""",
    """File Name: ({malware_url}[^,]{1,2000})""",
    """Event Type:\s{0,100}({alert_type}[^,]{1,2000})""",
    """Event Name: ({alert_name}[^,]{1,2000})""",
    """Cylance Score: ({alert_severity}\d{1,100})""",
    """Device Name: ({src_host}[^,]{1,2000})""",
    """IP Address: \(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """Path: ({process_directory}[^,]{1,2000})\\({process_name}[^,]{1,2000})?""",
    """Threat Classification:\s{0,100}({alert_name}[^,]{1,2000}),""",
    """Status:\s{0,100}({outcome}[^,]{1,2000}),""",
    """MD5:\s{0,100}({md5}[^,]{1,2000}),""",
    """File Owner:\s{0,100}(({domain}[^\\,]{1,2000})\\)?({user}[^,]{1,2000}),""",
    """SHA256:\s{0,100}({sha256}[^,]{1,2000}),""",
    """Detected By:\s{0,100}({additional_info}[^,]{1,2000})"""
  ]
  DupFields = ["malware_url->process_name"]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "src_host->malwareVictimHost", "alert_severity->sourceSeverity", "malware_url->malwareAttackerFile"]
    NameTemplate = """Cylance Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```