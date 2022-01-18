#### Parser Content
```Java
{
Name = cef-bit9-epp-alert
  Vendor = VMware
  Product = VMware Carbon Black App Control
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """|Bit9|""", """|Security alert|""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\|Bit9(\|[^\|]{1,2000}){3}\|({alert_name}[^\|]{1,2000})\|""",
    """cat=({alert_type}.+?)\s{1,100}\w+=""",
    """\|({alert_severity}[^\|]{1,2000})\|\w+=""",
    """externalId=({alert_id}\d{1,100})""",
    """dst=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """dhost=([^\\]{1,2000}\\+)?({src_host}[\w\-.]{1,2000})\s{0,100}(\w+=|$)""",
    """dvchost=([^\\]{1,2000}\\+)?({host}[^\s]{1,2000})\s{1,100}\w+=""",
    """filePath=({malware_url}.+?)\s{1,100}\w+=""",
    """filePath=({malware_url_path}\w+:\/\/.+?)\s{1,100}\w+=""",
    """filePath=(?!\w+:\/\/)({process}.+?)\s{1,100}\w+=""",
    """msg=({additional_info}.+?)\s{1,100}\w+=""",
    """fname=({process_name}.*?)\s\w+=""",
  ]
  SOAR {
      IncidentType = "malware"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_host->malwareVictimHost", "alert_type->description", "malware_url_path->malwareAttackerUrl", "file_path->malwareAttackerFile"]
      NameTemplate = """Carbon Black Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name ="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]

}
```