#### Parser Content
```Java
{
Name = syslog-symantec-dlp-alert-1
  Conditions = [ """Incident_Snapshot=""", """Device_Instance_ID=""", """Policy_Rules=""" ]
  Fields = ${SymantecParserTemplates.syslog-symantec-dlp-alert.Fields} [
      """(?i)incident_snapshot=[^,]*?({alert_id}\d+),""",
      """(?i)incident_snapshot="*\w+:\/+[^\s]*?((?!\d{1,3}\.\d{1,3}\.\d{1,3})({top_domain}[^\/\.\s]+(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|local))+))(\/|\||"|\s+\w+=|\s*$)"""
  ]
}
```