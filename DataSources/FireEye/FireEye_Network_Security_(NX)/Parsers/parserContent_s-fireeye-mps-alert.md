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
    """dvchost=({host}[^,]{1,2000})""",
    """alertid=({alert_id}\d{1,100})""",
    """alertType=({alert_type}[^,]{1,2000})""",
    """alertType=({alert_name}[^,]{1,2000})""",
    """sev=({alert_severity}[^,]{1,2000})""",
    """sname=({alert_name}[^,]{1,2000})""",
    """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """shost=({src_host}[^,]{1,2000})""",
    """cnchost=(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^,]{1,2000}))""",
    """dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """dhost=({dest_host}[^,]{1,2000})""",
    """~+User-Agent:\s{1,100}({user_agent}.+?)::""",
    """mwurl=({malware_url}[^,]{1,2000})"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_ip->malwareVictimHost", "malware_url->malwareAttackerUrl", "dest_ip->malwareAttackerIp"]
    NameTemplate = """FireEye Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```