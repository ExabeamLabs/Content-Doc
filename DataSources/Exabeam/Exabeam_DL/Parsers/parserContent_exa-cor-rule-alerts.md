#### Parser Content
```Java
{
Name = exa-cor-rule-alerts
  Vendor = Exabeam
  Product = Exabeam DL
  Lms = Exabeam
  DataType = "exabeam-security-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """exa_rule_name""", """exa_rule_category""", """exa_rule_id"""]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """(?:\W|")exa_rawEventTime(:|=)"{0,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)\s({host}[^\s]+)\sExabeam\s""",
    """(?:\W|")user"{0,20}(:|=)"{0,20}\s{0,100}({user}[^"|]+?)\s{0,100}(?:\||")""",
    """(?:\W|")host"{0,20}(:|=)"{0,20}\s{0,100}({host}[^"|]+?)\s{0,100}(?:\||")""",
    """(?:\W|")query_key_value"{0,20}(:|=)"{0,20}\s{0,100}({malware_url}[^"|]+?)\s{0,100}(?:\||")""",
    """(?:\W|")compare_key_value"{0,20}(:|=)"{0,20}\s{0,100}({additional_info}[^"|]+?)\s{0,100}(?:\||")""",
    """(?:\W|")cardinality_field_value"{0,20}(:|=)"{0,20}\s{0,100}({additional_info}[^"|]+?)\s{0,100}(?:\||")""",
    """(?:\W|")exa_rule_id"{0,20}(:|=)"{0,20}\s{0,100}({alert_id}[^"|]+?)\s{0,100}(?:\||")""",
    """(?:\W|")exa_rule_severity"{0,20}(:|=)"{0,20}\s{0,100}({alert_severity}[^"|]+?)\s{0,100}(?:\||")""",
    """(?:\W|")exa_rule_category"{0,20}(=|:)"{0,20}\s{0,100}({alert_type}[^"|]+?)\s{0,100}(?:\||")""",
    """(?:\W|")exa_rule_name"{0,20}(:|=)"{0,20}\s{0,100}({alert_name}[^"|]+?)\s{0,100}(?:\||")""",
    """(?:\W|")src_ip"{0,20}(:|=)"{0,20}\s{0,100}({src_ip}[a-fA-F:\d.]+)\s{0,100}(?:\||")""",
    """(?:\W|")dest_ip"{0,20}(:|=)"{0,20}\s{0,100}({dest_ip}[a-fA-F:\d.]+)\s{0,100}(?:\||")""",
    """(?:\W|")exa_link_logs"{0,20}(:|=)"{0,20}\s{0,100}({dl_exa_link_logs}[^"|]+?)\s{0,100}(?:\||")""",
    """(?:\W|")exa_link_alert"{0,20}(:|=)"{0,20}\s{0,100}({dl_exa_link_alert}[^"|]+?)\s{0,100}(?:\||")""",
    """(?:\W|")src_host"{0,20}(:|=)"{0,20}\s{0,100}({src_host}[^"|]+?)\s{0,100}(?:\||")""",
    """(?:\W|")dest_host"{0,20}(:|=)"{0,20}\s{0,100}({dest_host}[^"|]+?)\s{0,100}(?:\||")""",
    """exa_rule_description(:|=)"{0,20}({top_reasons}[^"\|]+?)\s{0,100}(?:\||")""",
    """exa_risk_score"{0,20}(:|=)"{0,20}\s{0,100}({risk_score}[^"|]+?)\s{0,100}(?:\||")"""
    """(?:\W|")original_doc_message"{0,20}(=|:)"{0,20}\s{0,100}({rule_description}[^"|]+?)\s{0,100}(?:\||")""",
  ]
  SOAR {
    IncidentType = "ueba"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "top_reasons->uebaRiskReasons","dl_exa_link_alert->uebaSessionLink", "user->uebaUserId", "risk_score->uebaSessionRiskScore", "rule_description->description", "alert_severity->sourceSeverity", "alert_id->sourceId"]
    NameTemplate = """Exabeam Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```