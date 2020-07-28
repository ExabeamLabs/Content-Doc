#### Parser Content
```Java
{
Name = syslog-symantec-dlp-alert-4
  Conditions = [ """,endpoint_machine=""", """,policy=""", """,incident_id=""" ]
  Fields = ${SymantecParserTemplates.syslog-symantec-dlp-alert.Fields} [
    """(?i)policy="*({alert_name}[^",]+)("|,|\s*$)""",
    """(?i)application_name="*(?:N\/A|({process_name}.+?))\s*("|,|\s*$)""",
    """\s*(?i)file_name="*(?:N\/A|({file_name}[^",]+))\s*("|,|\s*$)"""
  ]
}
```