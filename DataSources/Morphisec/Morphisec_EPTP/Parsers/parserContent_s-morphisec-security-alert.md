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
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """({host}[\w\.-]+)\s{1,100}Morphisec-Server""",
    """"attack_time_dt"\s{0,100}:\s{0,100}\[\s{0,100}"({time}[^"]+)"""",
    """({alert_name}attack)""",
    """"machine_s"\s{0,100}:\s{0,100}\[\s{0,100}"({src_host}[^"]+)"""",
    """"ip_addr_s"\s{0,100}:\s{0,100}\[\s{0,100}"({src_ip}[^"]+)"""",
    """"application_s"\s{0,100}:\s{0,100}\[\s{0,100}"({malware_url}[^"]+)"""",
    """"user_s"\s{0,100}:\s{0,100}\[\s{0,100}"(({domain}[^"]+)[\\\/])?({user}[^"]+)"""",
    """"attack_module_s"\s{0,100}:\s{0,100}\[\s{0,100}"({attack_module}[^"]+)"""",
    """"suspicious_files_ss"\s{0,100}:\s{0,100}\[\s{0,100}\[\s{0,100}(""|({suspicious_files}.+?))\s{0,100}\]\s{0,100}\]\s{0,100}[,\]\}]""",
    """"suspicious_urls_ss"\s{0,100}:\s{0,100}\[\s{0,100}\[\s{0,100}(""|({suspicious_urls}.+?))\s{0,100}\]\s{0,100}\]\s{0,100}[,\]\}]""",
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