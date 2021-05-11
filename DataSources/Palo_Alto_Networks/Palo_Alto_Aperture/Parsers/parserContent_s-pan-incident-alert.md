#### Parser Content
```Java
{
Name = s-pan-incident-alert
    Vendor = Palo Alto Networks
    Product = Palo Alto Aperture
    Lms = Splunk
    DataType = "dlp-alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """"incident"""", "cloud_app_instance" ]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)Z""",
      """exabeam_host=({host}[^\s]+)""",
      """\Wpolicy_rule_name\s{0,100}=\s{0,100}"({alert_name}[^"]+)"""",
      """\Witem_type\s{0,100}=\s{0,100}"({item_type}[^"]+)"""",
      """\Witem_name\s{0,100}=\s{0,100}"({item_name}[^"]+)"""",
      """\Witem_owner\s{0,100}=\s{0,100}"({user_firstname}[^",\s]+)\s{1,100}({user_lastname}[^",\s]+)"""",
      """\Witem_owner\s{0,100}=\s{0,100}"({user_lastname}[^",\s]+)\s{0,100}\,\s{0,100}({user_firstname}[^",\s]+)"""",
      """\Witem_owner\s{0,100}=\s{0,100}"({user}[^",\s@]+)"""",
      """\Wcloud_app_instance\s{0,100}=\s{0,100}"({alert_type}[^"]+)"""",
      """"policy_rule_name":"({alert_name}[^"]+)""",
      """"item_type":"({item_type}[^"]+)""",
      """"item_name":"({item_name}[^"]+)""",
      """"item_owner":"({user_firstname}[^",\s]+)\s{1,100}({user_lastname}[^",\s]+)"""",
      """"item_owner":"({user}[^",\s@]+)"""",
      """"cloud_app_instance":"({alert_type}[^"]+)""",
      """"item_creator":"(|({item_creator}[^"]+))"""",
      """"item_creator_email":"(|({user_email}[^"]+))"""",
      """"collaborators":"(|({collaborators}[^"]+))"""",
      """ext_severity=({alert_severity}[^\s]+)"""
    ]
    SOAR {
    IncidentType = "dlp"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "user->dlpFileOwner", "item_name->dlpFileName", "alert_name->dlpPolicy", "host->dlpDeviceName", "alert_type->description"]
    NameTemplate = """Palo Alto DLP Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="user", Name="windows_id", Fields=["user->windows_id"]}
```