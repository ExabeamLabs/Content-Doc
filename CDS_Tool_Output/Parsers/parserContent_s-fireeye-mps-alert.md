#### Parser Content
```Java
{
Name = s-fireeye-mps-alert
  Vendor = FireEye
  Product = FireEye Network Security (NX)
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "CSV:0:FireEye:Web MPS" ]
  Fields = [ 
    """,occurred=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """dvchost=({host}[^,]+)""",
    """alertid=({alert_id}\d+)""",
    """alertType=({alert_type}[^,]+)""",
    """alertType=({alert_name}[^,]+)""",
    """sev=({alert_severity}[^,]+)""",
    """sname=({alert_name}[^,]+)""",
    """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """shost=({src_host}[^,]+)""",
    """cnchost=(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^,]+))""",
    """dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """dhost=({dest_host}[^,]+)""",
    """~+User-Agent:\s+({user_agent}.+?)::""",
    """mwurl=({malware_url}[^,]+)"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_ip->malwareVictimHost", "malware_url->malwareAttackerUrl", "dest_ip->malwareAttackerIp"]
    NameTemplate = """FireEye Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```