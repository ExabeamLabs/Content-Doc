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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """(?:\W|")exa_rawEventTime(:|=)"{0,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)\s({host}[^\s]{1,2000})\sExabeam\s""",
    """(?:\W|")user"{0,20}(:|=)\\?"{0,20}\s{0,100}({user}[^"|]{1,2000}?)\s{0,100}(?:\||\\?")""",
    """(?:\W|")host"{0,20}(:|=)\\?"{0,20}\s{0,100}({host}[^"|]{1,2000}?)\s{0,100}(?:\||\\?")""",
    """(?:\W|")query_key_value"{0,20}(:|=)"{0,20}\s{0,100}({malware_url}[^"|]{1,2000}?)\s{0,100}(?:\||")""",
    """(?:\W|")compare_key_value"{0,20}(:|=)"{0,20}\s{0,100}({additional_info}[^"|]{1,2000}?)\s{0,100}(?:\||")""",
    """(?:\W|")cardinality_field_value"{0,20}(:|=)"{0,20}\s{0,100}({additional_info}[^"|]{1,2000}?)\s{0,100}(?:\||")""",
    """(?:\W|")exa_rule_id"{0,20}(:|=)"{0,20}\s{0,100}({alert_id}[^"|]{1,2000}?)\s{0,100}(?:\||")""",
    """(?:\W|")exa_rule_severity"{0,20}(:|=)"{0,20}\s{0,100}({alert_severity}[^"|]{1,2000}?)\s{0,100}(?:\||")""",
    """(?:\W|")exa_rule_category"{0,20}(=|:)"{0,20}\s{0,100}({alert_type}[^"|]{1,2000}?)\s{0,100}(?:\||")""",
    """(?:\W|")exa_rule_name"{0,20}(:|=)"{0,20}\s{0,100}({alert_name}[^"|]{1,2000}?)\s{0,100}(?:\||")""",
    """(?:\W|")src(_ip)?"{0,20}(:|=)"{0,20}\s{0,100}({src_ip}[a-fA-F:\d.]{1,2000})\s{0,100}(?:\||"|\s{1,100}\w+=)""",
    """(?:\W|")dest_ip"{0,20}(:|=)"{0,20}\s{0,100}({dest_ip}[a-fA-F:\d.]{1,2000})\s{0,100}(?:\||"|\s{1,100}\w+=)""",
    """(?:\W|")exa_link_logs"{0,20}(:|=)"{0,20}\s{0,100}({dl_exa_link_logs}[^"|]{1,2000}?)\s{0,100}(?:\||")""",
    """(?:\W|")exa_link_alert"{0,20}(:|=)"{0,20}\s{0,100}({dl_exa_link_alert}[^"|]{1,2000}?)\s{0,100}(?:\||")""",
    """(?:\W|")src_host"{0,20}(:|=)\\?"{0,20}\s{0,100}({src_host}[^"|]{1,2000}?)\s{0,100}(?:\||\\?")""",
    """(?:\W|")dest_host"{0,20}(:|=)\\?"{0,20}\s{0,100}({dest_host}[^"|]{1,2000}?)\s{0,100}(?:\||\\?")""",
    """exa_rule_description(:|=)"{0,20}({top_reasons}[^"\|=]{1,2000}?)\s{0,100}(?:\||"|\s{1,100}\w+=)""",
    """exa_risk_score"{0,20}(:|=)"{0,20}\s{0,100}({risk_score}[^"|]{1,2000}?)\s{0,100}(?:\||")""",
    """(?:\W|")original_doc_message"{0,20}(=|:)\\?"{0,20}(\{({rule_description}[^\}]{1,2000})|\s{0,100}({=rule_description}[^"|]{1,2000}?))\s{0,100}(?:\||\\?"|\})""",
    """\srule_description=\\?"({rule_description}[^"]{1,2000})""""
  ]
  DupFields = ["risk_score->score"]
  SOAR {
    IncidentType = "ueba"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "top_reasons->uebaRiskReasons","dl_exa_link_alert->uebaSessionLink", "user->uebaUserId", "risk_score->uebaSessionRiskScore", "rule_description->description", "alert_severity->sourceSeverity", "alert_id->sourceId"]
    NameTemplate = """Exabeam Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name ="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]

}
```