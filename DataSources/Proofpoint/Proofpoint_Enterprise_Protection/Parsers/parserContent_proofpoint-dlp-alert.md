#### Parser Content
```Java
{
Name = proofpoint-dlp-alert
  DataType = "dlp-alert"
  Conditions = [ """"sub_type": "Data Leakage"""", """"related_events_0_event_id":""", """"related_events_0_user_email":""", """"severity":""" ]
  Fields = ${PPParserTemplates.proofpoint-alert.Fields}[
    """"related_events_0_cloud_service":\s*"({target}[^"]+)"""",
    """"related_events_0_user_agent":\s*"({user_agent}[^"]+)""""
  ]
  DupFields = [ "alert_name->policy"]

}
proofpoint-alert = {
  Vendor = Proofpoint
  Product = Proofpoint CASB
  Lms = Splunk
  TimeFormat = "epoch_sec"
  Fields = [
    """"timestamp":\s*({time}\d+)""",
    """exabeam_host=({host}[^\s]+)""",
    """"related_events_0_intelligence_0_ip_address":\s*"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"title":\s*"({alert_name}[^"]+)"""",
    """"severity":\s*"({alert_severity}[^"]+)"""",
    """"sub_type":\s*"({alert_type}[^"]+)"""",
    """"related_events_0_event_classification_category":\s*"({event_name}[^"]+)"""",
    """"related_events_0_full_name":\s*"({user_fullname}[^"]+)"""",
    """"related_events_0_user_email":\s*"({user_email}[^@]+@[^.]+\.[^"]+)"""",
    """"id":\s*"({alert_id}[^"]+)"""",
    """"description":\s*"({additional_info}[^"]+)"""",
    ]

```