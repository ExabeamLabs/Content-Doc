#### Parser Content
```Java
{
Name = q-bit9-epp-alert
  Vendor = Carbon Black
  Product = Cb Protection
  Lms = QRadar
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "LEEF:", "Bit9|Parity" ]
  Fields = [
    """\|cat=(?!General Management).+?devTime=({time}\w+ \d+ \d+ \d\d:\d\d:\d\d)""",
    """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
    """Bit9\|Parity\|[^\|]+\|({alert_name}[^\|]+)\|cat=({alert_type}.+?)\s+sev""",
    """sev=({alert_severity}[\d]+)""",
    """externalId=({alert_id}[\d]+)""",
    """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """srcHostName=({domain}[^\\]+)\\?({src_host}[^\s]+)""",
    """usrName=({user}[^\s]+)""",
    """filePath=({malware_url}.+?)\s+fileName""",
    """filePath=({malware_url_path}\w+:\/\/.+?)\s+fileName""",
    """filePath=({file_path}(?!\w+:\/\/).+?)\s+fileName""",
    """dstHostName=({dest_host}[^\s]+)"""
  ]
  SOAR {
      IncidentType = "malware"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_host->malwareVictimHost", "alert_type->description", "malware_url_path->malwareAttackerUrl", "file_path->malwareAttackerFile"]
      NameTemplate = """Carbon Black Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```