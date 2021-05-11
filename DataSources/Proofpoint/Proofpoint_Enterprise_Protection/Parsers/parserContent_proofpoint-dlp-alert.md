#### Parser Content
```Java
{
Name = proofpoint-dlp-alert
  DataType = "dlp-alert"
  Conditions = [ """"sub_type": "Data Leakage"""", """"related_events_0_event_id":""", """"related_events_0_user_email":""", """"severity":""" ]
  Fields = ${PPParserTemplates.proofpoint-alert.Fields}[
    """"related_events_0_cloud_service":\s{0,100}"({target}[^"]+)"""",
    """"related_events_0_user_agent":\s{0,100}"({user_agent}[^"]+)""""
  ]
  DupFields = [ "alert_name->policy"]

}
proofpoint-alert = {
  Vendor = Proofpoint
  Product = Proofpoint CASB
  Lms = Splunk
  TimeFormat = "epoch_sec"
  Fields = [
    """"timestamp":\s{0,100}({time}\d{1,100})""",
    """exabeam_host=({host}[^\s]+)""",
    """"related_events_0_intelligence_0_ip_address":\s{0,100}"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"title":\s{0,100}"({alert_name}[^"]+)"""",
    """"severity":\s{0,100}"({alert_severity}[^"]+)"""",
    """"sub_type":\s{0,100}"({alert_type}[^"]+)"""",
    """"related_events_0_event_classification_category":\s{0,100}"({event_name}[^"]+)"""",
    """"related_events_0_full_name":\s{0,100}"({user_fullname}[^"]+)"""",
    """"related_events_0_user_email":\s{0,100}"({user_email}[^@]+@[^.]+\.[^"]+)"""",
    """"id":\s{0,100}"({alert_id}[^"]+)"""",
    """"description":\s{0,100}"({additional_info}[^"]+)"""",
    ]

```