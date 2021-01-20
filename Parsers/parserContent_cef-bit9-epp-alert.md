#### Parser Content
```Java
{
Name = cef-bit9-epp-alert
  Vendor = Carbon Black
  Product = Cb Protection
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """|Bit9|""", """|Security alert|""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\|Bit9(\|[^\|]+){3}\|({alert_name}[^\|]+)\|""",
    """cat=({alert_type}.+?)\s+\w+=""",
    """\|({alert_severity}[^\|]+)\|\w+=""",
    """externalId=({alert_id}\d+)""",
    """dst=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """dhost=([^\\]+\\+)?({src_host}[\w\-.]+)\s*(\w+=|$)""",
    """dvchost=([^\\]+\\+)?({host}[^\s]+)\s+\w+=""",
    """filePath=({malware_url}.+?)\s+\w+=""",
    """filePath=({malware_url_path}\w+:\/\/.+?)\s+\w+=""",
    """filePath=(?!\w+:\/\/)({process}.+?)\s+\w+=""",
    """msg=({additional_info}.+?)\s+\w+=""",
    """fname=({process_name}.*?)\s\w+=""",
  ]
  SOAR {
      IncidentType = "malware"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_host->malwareVictimHost", "alert_type->description", "malware_url_path->malwareAttackerUrl", "file_path->malwareAttackerFile"]
      NameTemplate = """Carbon Black Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```