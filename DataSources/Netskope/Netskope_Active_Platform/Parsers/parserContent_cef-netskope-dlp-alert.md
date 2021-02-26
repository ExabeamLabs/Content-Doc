#### Parser Content
```Java
{
Name = cef-netskope-dlp-alert
  DataType = "dlp-alert"
  Conditions = [ """CEF:""", """|Skyformation|""", """"type":"""", """destinationServiceName=Netskope""", """"alert_type":"DLP"""" ]
  Fields = ${NetskopeParserTemplates.cef-netskope-activity.Fields}[
    """"policy":"({alert_name}[^"]+)""",
    """"dlp_rule_severity":"({alert_severity}[^"]+)""",
    """"dlp_incident_id":({alert_id}\d+)""",
    """"from_user":"({from_user_at}[^",]+)"""",
    """"sha256":"({sha256_at}[^",]+)"""",
    """"site":"({site_at}[^",]+)"""",
    """"owner":"({file_owner_at}[^"]+)"""",
    """"dlp_file":"({file_path_at}[^"]+)"""",
    """"shared_with":"({shared_with_at}[^"]+)""""
  ]
  DupFields = [ "activity->alert_type", "object->file_name" ]
}
```