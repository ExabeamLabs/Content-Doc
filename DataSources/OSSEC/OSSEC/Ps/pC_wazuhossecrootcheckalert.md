#### Parser Content
```Java
{
Name = wazuh-ossec-rootcheck-alert
  Vendor = OSSEC
  Product = OSSEC
  DataType = "alert"
  Conditions = [ """"pg.alert_name":"Host-based anomaly detection event (rootcheck).""", """ossec""", """Wazuh""" ]
  Fields = ${WazuhParserTemplates.wazuh-catch-all-template.Fields} [
    """"data.file":"[^"]{1,2000}?"""",
    """"pg.destination.site.name":"({additional_info}[^"]{1,2000}?)"""" 
    """"rule.description":"({alert_type}[^"]{1,2000}?)""""
    """"data.title":"({alert_name}[^"]{1,2000}?)"""",
    """"agent.labels.network.ipv4.primary":"({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"""",
    """"agent.labels.agent_hostname":"({src_host}[^"]{1,2000})"""", 
  ]
}
```