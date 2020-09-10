#### Parser Content
```Java
{
Name = s-morphisec-security-alert
  Vendor = Morphisec
  Product = Morphisec EPTP
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """"attack_module_s"""",""""attack_time_dt""""]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """({host}[\w\.-]+)\s+Morphisec-Server""",
    """"attack_time_dt"\s*:\s*\[\s*"({time}[^"]+)"""",
    """({alert_name}attack)""",
    """"machine_s"\s*:\s*\[\s*"({src_host}[^"]+)"""",
    """"ip_addr_s"\s*:\s*\[\s*"({src_ip}[^"]+)"""",
    """"application_s"\s*:\s*\[\s*"({malware_url}[^"]+)"""",
    """"user_s"\s*:\s*\[\s*"(({domain}[^"]+)[\\\/])?({user}[^"]+)"""",
    """"attack_module_s"\s*:\s*\[\s*"({attack_module}[^"]+)"""",
    """"suspicious_files_ss"\s*:\s*\[\s*\[\s*(""|({suspicious_files}.+?))\s*\]\s*\]\s*[,\]\}]""",
    """"suspicious_urls_ss"\s*:\s*\[\s*\[\s*(""|({suspicious_urls}.+?))\s*\]\s*\]\s*[,\]\}]""",
  ]
  DupFields = ["alert_name->alert_type"]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "src_host->malwareVictimHost", "suspicious_files->malwareAttackerFile"]
    NameTemplate = """Morphisec Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```