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
    """exabeam_host=({host}[\w.\-]+)""",
    """\[({host}[\w\-.]+)\]\s{0,100}Event Type:""",
    """Date: ({time}\d{1,100}\/\d{1,100}\/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \w+)""",
    """File Name: ({malware_url}[^,]+)""",
    """Event Type:\s{0,100}({alert_type}[^,]+)""",
    """Event Name: ({alert_name}[^,]+)""",
    """Cylance Score: ({alert_severity}\d{1,100})""",
    """Device Name: ({src_host}[^,]+)""",
    """IP Address: \(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """Path: ({process_directory}[^,]+)\\({process_name}[^,]+)?""",
    """Threat Classification:\s{0,100}({alert_name}[^,]+),""",
    """Status:\s{0,100}({outcome}[^,]+),""",
    """MD5:\s{0,100}({md5}[^,]+),""",
    """File Owner:\s{0,100}(({domain}[^\\,]+)\\)?({user}[^,]+),""",
    """SHA256:\s{0,100}({sha256}[^,]+),""",
    """Detected By:\s{0,100}({additional_info}[^,]+)"""
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