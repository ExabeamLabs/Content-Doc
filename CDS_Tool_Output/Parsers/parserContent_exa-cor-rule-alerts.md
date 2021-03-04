#### Parser Content
```Java
{
Name = exa-cor-rule-alerts
  Vendor = Exabeam
  Product = Exabeam DL
  Lms = Exabeam
  DataType = "exabeam-security-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """exa_rule_name:""", """exa_rule_category:""", """exa_rule_id:"""]
  Fields = [
    """exa_rawEventTime:({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """exa_rule_category:\s*({alert_type}.+?)\s*\|""",
    """exa_rule_name:\s*({alert_name}.+?)\s*\|""",
    """exa_rule_severity:\s*({alert_severity}.+?)\s*\|""",
    """exa_rule_id:\s*({alert_id}.+?)\s*\|""",
    """src_ip:\s*({src_ip}[^\s]*)""",
    """dest_ip:\s*({dest_ip}[^\s]*)""",
    """src_host:\s*({src_host}[^\s]*)""",
    """dest_host:\s*({dest_host}[^\s]*)""",
    """host:\s*({host}[^\s]*)""",
    """user:\s*({user}.+?)\s*\|""",
    """query_key_value:\s*({malware_url}.+?)\s*\|""",
    """compare_key_value:\s*({additional_info}.+?)\s*\|""",
    """cardinality_field_value:\s*({additional_info}.+?)\s*\|""",
    """exa_link_logs:\s*({dl_exa_link_logs}.+?)\s*\|"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_host->malwareVictimHost", "alert_type->description", "malware_url->malwareAttackerUrl"]
    NameTemplate = """Exabeam Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```