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

wazuh-catch-all-template {
    Lms = Direct
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """"@timestamp":"({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)"""
      """"data.dstuser":"(\(no user\)|({dest_user}[^"]{1,2000}))"""
      """"location":"({log_location}[^"]{1,2000})"""
      """"path":"({log_path}[^"]{1,2000})"""
      """"agent.id":"({agent_id}\d{1,100})"""
      """"manager.name":"({wazuh_manager}[^"]{1,2000})"""
      """"rule.description":"({description}[^"]{1,2000})"""
      """"decoder.name":"({decoder_name}[^"]{1,2000})"""
      """"rule.id":"({rule_id}\d{1,100})"""
      """"agent.name":"({agent_name}[^"]{1,2000})"""
      """"agent.id":"({agent_id}[^"]{1,2000})"""
      """"data.srcip":"({src_ip}[:0-9a-fA-F\.]{1,2000})"""
      """"data.status":"({outcome}[^"]{1,2000})"""
      """"data.data":"({data}[^"]{1,2000})"""
      """"predecoder.hostname":"({host}[^"]{1,2000})"""
      """"data.system_name":"({host}[^"]{1,2000})"""
    ]
    DupFields = [ "description->event_name" 
}
```