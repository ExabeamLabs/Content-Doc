#### Parser Content
```Java
{
Name = q-bit9-epp-alert
  Vendor = VMware
  Product = VMware Carbon Black App Control
  Lms = QRadar
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "LEEF:", "Bit9|Parity" ]
  Fields = [
    """\|cat=(?!General Management).+?devTime=({time}\w+ \d{1,100} \d{1,100} \d\d:\d\d:\d\d)""",
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
    """Bit9\|Parity\|[^\|]{1,2000}\|({alert_name}[^\|]{1,2000})\|cat=({alert_type}.+?)\s{1,100}sev""",
    """sev=({alert_severity}[\d]{1,2000})""",
    """externalId=({alert_id}[\d]{1,2000})""",
    """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """srcHostName =({domain}[^\\]{1,2000})\\?({src_host}[^\s]{1,2000})""",
    """usrName =({user}[^\s]{1,2000})""",
    """filePath=({malware_url}.+?)\s{1,100}fileName""",
    """filePath=({malware_url_path}\w+:\/\/.+?)\s{1,100}fileName""",
    """filePath=({file_path}(?!\w+:\/\/).+?)\s{1,100}fileName""",
    """dstHostName =({dest_host}[^\s]{1,2000})"""
  ]
  SOAR {
      IncidentType = "malware"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_host->malwareVictimHost", "alert_type->description", "malware_url_path->malwareAttackerUrl", "file_path->malwareAttackerFile"]
      NameTemplate = """Carbon Black Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name ="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]

}
```