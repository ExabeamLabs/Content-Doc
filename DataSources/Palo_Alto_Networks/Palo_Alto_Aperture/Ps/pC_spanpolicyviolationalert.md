#### Parser Content
```Java
{
Name = s-pan-policyviolation-alert
    Vendor = Palo Alto Networks
    Product = Palo Alto Aperture
    Lms = Splunk
    DataType = "dlp-alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """"policy_violation"""", "cloud_app_instance" ]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)Z""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """\Wpolicy_rule_name\s{0,100}=\s{0,100}"({alert_name}[^"]{1,2000})"""",
      """\Witem_type\s{0,100}=\s{0,100}"({item_type}[^"]{1,2000})"""",
      """\Witem_type\s{0,100}=\s{0,100}"user"(\s{0,100}\w+\s{0,100}=\s{0,100}"[^"]{0,2000}")*\s{0,100}item_name\s{0,100}=\s{0,100}"({user_email}[^"]{1,2000})"""",
      """\Witem_name\s{0,100}=\s{0,100}"({user_email}[^"]{1,2000})"(\s{0,100}\w+\s{0,100}=\s{0,100}"[^"]{0,2000}")*\s{0,100}item_type\s{0,100}=\s{0,100}"user"""",
      """\Wcloud_app_instance\s{0,100}=\s{0,100}"({alert_type}[^"]{1,2000})"""",
      """\Waction_taken\s{0,100}=\s{0,100}"({additional_info}[^"]{1,2000})"""",
      """"policy_rule_name":"({alert_name}[^"]{1,2000})""",
      """"item_type":"({item_type}[^"]{1,2000})""",
      """"item_type":"user".*?"item_name":"({user_email}[^"]{1,2000})""",
      """"item_name":"({user_email}[^"]{1,2000})".*?"item_type":"user"""",
      """"cloud_app_instance":"({alert_type}[^"]{1,2000})""",
      """"action_taken":"({additional_info}[^"]{1,2000})""",
      """"item_creator":"(|({item_creator}[^"]{1,2000}))"""",
      """"item_creator_email":"(|({user_email}[^"]{1,2000}))"""",
      """"collaborators":"(|({collaborators}[^"]{1,2000}))"""",
      """"severity":({alert_severity}[\d.]{1,2000})"""
    ]
    SOAR {
    IncidentType = "dlp"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "user->dlpUser", "alert_name->dlpPolicy", "alert_type->description", "host->dlpDeviceName"]
    NameTemplate = """Palo Alto DLP Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="user", Name ="windows_id", Fields=["user->windows_id"]

}
```