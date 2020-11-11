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
      """\Wpolicy_rule_name\s*=\s*"({alert_name}[^"]+)"""",
      """\Witem_type\s*=\s*"({item_type}[^"]+)"""",
      """\Witem_name\s*=\s*"({item_name}[^"]+)"""",
      """\Witem_owner\s*=\s*"({user}({user_firstname}[^",\s]+)\s+({user_lastname}[^",\s]+))"""",
      """\Witem_owner\s*=\s*"({user}({user_lastname}[^",\s]+)\s*\,\s*({user_firstname}[^",\s]+))"""",
      """\Wcloud_app_instance\s*=\s*"({alert_type}[^"]+)"""",
    ]
    SOAR {
    IncidentType = "dlp"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "user->dlpFileOwner", "item_name->dlpFileName", "alert_name->dlpPolicy", "host->dlpDeviceName", "alert_type->description"]
    NameTemplate = """Palo Alto DLP Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="user", Name="windows_id", Fields=["user->windows_id"]}
      ]
    }
  }
```