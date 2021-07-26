#### Parser Content
```Java
{
Name = proofpoint-dlp-alert
  DataType = "dlp-alert"
  Conditions = [ """"sub_type": "Data Leakage"""", """"related_events_0_event_id":""", """"related_events_0_user_email":""", """"severity":""" ]
  Fields = ${PPParserTemplates.proofpoint-alert.Fields}[
    """"related_events_0_cloud_service":\s{0,100}"({target}[^"]{1,2000})"""",
    """"related_events_0_user_agent":\s{0,100}"({user_agent}[^"]{1,2000})""""
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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"related_events_0_intelligence_0_ip_address":\s{0,100}"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"title":\s{0,100}"({alert_name}[^"]{1,2000})"""",
    """"severity":\s{0,100}"({alert_severity}[^"]{1,2000})"""",
    """"sub_type":\s{0,100}"({alert_type}[^"]{1,2000})"""",
    """"related_events_0_event_classification_category":\s{0,100}"({event_name}[^"]{1,2000})"""",
    """"related_events_0_full_name":\s{0,100}"({user_fullname}[^"]{1,2000})"""",
    """"related_events_0_user_email":\s{0,100}"({user_email}[^@]{1,2000}@[^.]{1,2000}\.[^"]{1,2000})"""",
    """"id":\s{0,100}"({alert_id}[^"]{1,2000})"""",
    """"description":\s{0,100}"({additional_info}[^"]{1,2000})"""",
    ]

```