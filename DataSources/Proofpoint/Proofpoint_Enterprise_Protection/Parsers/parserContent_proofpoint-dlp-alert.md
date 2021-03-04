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
```