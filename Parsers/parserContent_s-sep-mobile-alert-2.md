#### Parser Content
```Java
{
Name = s-sep-mobile-alert-2
  Conditions = [ """"type":"DeviceCompromised"""" , """current_risk_warnings""", """health_status""", """mdm_status""", """kill_chain_incident_ids""" ]
  Fields = ${SymantecParserTemplates.s-sep-mobile-alert.Fields}[
    """"severity":\s*"({alert_severity}[^"]+)".+?"id":\s*({alert_id}\d+)""",
    """"type":\s*"({alert_type}[^"]+)""",
  ]
}
```