#### Parser Content
```Java
{
Name = fireeye-json-alert-email
    Vendor = FireEye
    Product = FireEye Email Gateway
    Lms = Splunk
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [""""msg": """",""""product": "Email MPS"""",""""alert": {""", """malware-detected"""]
    Fields = [
      """"appliance": "({host}[^"]{1,2000})"""",
      """"smtp-to": "({user_email}[^"@]{1,2000}?@({domain}[^"]{1,2000}))""""
      """"smtp-mail-from": "({sender}[^"@]{1,2000}?@[^"]{1,2000})""""
      """"malware": \{.*?"name": "({alert_name}[^"]{1,2000})"""" 
      """({alert_type}malware-detected)"""
      """"severity": "({alert_severity}[^"]{1,2000})"""",
      """"occurred": "({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})""",
      """"id": "({alert_id}[^"]{1,2000})","""
      """"alert-url": "({additional_info}[^"]{1,2000})"""",
      """"action": "({outcome}[^"]{1,2000})"""",
      """"md5sum": "({md5}[^"]{1,2000})"""",
      """({category}Email)"""
    ]
    DupFields = ["alert_name->malware_file_name", "user_email->recipient"]
    SOAR {
        IncidentType = "malware"
        DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_id->sourceId", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "additional_info->sourceUrl"]
        NameTemplate = """FireEye Email MPS Alert ${alert_name} found"""
        ProjectName = "SOC"
  }
```