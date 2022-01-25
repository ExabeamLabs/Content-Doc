#### Parser Content
```Java
{
Name = s-pan-incident-alert
    Vendor = Palo Alto Networks
    Product = Palo Alto Aperture
    Lms = Splunk
    DataType = "dlp-alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """"incident"""", """"cloud_app_instance"""", """"item_owner":""", """"item_creator_email":""" ]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)Z""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """\Wpolicy_rule_name\s{0,100}=\s{0,100}"({alert_name}[^"]{1,2000})"""",
      """\Witem_type\s{0,100}=\s{0,100}"({item_type}[^"]{1,2000})"""",
      """\Witem_name\s{0,100}=\s{0,100}"({item_name}[^"]{1,2000})"""",
      """\Witem_owner\s{0,100}=\s{0,100}"({user_firstname}[^",\s]{1,2000})\s{1,100}({user_lastname}[^",\s]{1,2000})"""",
      """\Witem_owner\s{0,100}=\s{0,100}"({user_lastname}[^",\s]{1,2000})\s{0,100}\,\s{0,100}({user_firstname}[^",\s]{1,2000})"""",
      """\Witem_owner\s{0,100}=\s{0,100}"({user}[^",\s@]{1,2000})"""",
      """\Wcloud_app_instance\s{0,100}=\s{0,100}"({alert_type}[^"]{1,2000})"""",
      """"policy_rule_name":"({alert_name}[^"]{1,2000})""",
      """"item_type":"({item_type}[^"]{1,2000})""",
      """"item_name":"({item_name}[^"]{1,2000})""",
      """"item_owner":"({user_firstname}[^",\s]{1,2000})\s{1,100}({user_lastname}[^",\s]{1,2000})"""",
      """"item_owner":"({user}[^",\s@]{1,2000})"""",
      """"cloud_app_instance":"({alert_type}[^"]{1,2000})""",
      """"item_creator":"(|({item_creator}[^"]{1,2000}))"""",
      """"item_creator_email":"(|({user_email}[^\s",@]{1,2000}\@[\w\.\-]{1,2000}))"""",
      """"collaborators":"(|({collaborators}[^"]{1,2000}))"""",
      """ext_severity=({alert_severity}[^\s]{1,2000})"""
    ]
    SOAR {
    IncidentType = "dlp"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "user->dlpFileOwner", "item_name->dlpFileName", "alert_name->dlpPolicy", "host->dlpDeviceName", "alert_type->description"]
    NameTemplate = """Palo Alto DLP Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="user", Name ="windows_id", Fields=["user->windows_id"]

}
```