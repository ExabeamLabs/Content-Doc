#### Parser Content
```Java
{
Name = wazuh-ping-app-login-2
  Conditions = [ """"data.type":"SSO"""", """"type":"wazuh-alerts"""" ]
  Fields = ${WazuhParserTemplates.wazuh-ping-app-template.Fields} [
    """({event_code}SSO)"""
  ]

wazuh-ping-app-template {
    Vendor = Ping Identity
    Product = Ping Identity
    Lms = Direct
    DataType = "app-login"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [ 
      """"@timestamp":"({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)"""
      """"data.username":"(({user_email}[^"]{1,2000}?@[^"]{1,2000}?\.[^"]{1,2000}?)|({user}[^"]{1,2000}?))""""
      """"data.ip_address":"({src_ip}[:0-9a-fA-F\.]{1,2000})\s{0,100}""""
      """"data.hostname":"({host}[^"]{1,2000})"""
      """"data.status":"({outcome}[^"]{1,2000})""" 
      """"location":"({log_location}[^"]{1,2000})"""
      """"path":"({log_path}[^"]{1,2000})"""
      """"agent.id":"({agent_id}\d{1,100})"""
      """"manager.name":"({wazuh_manager}[^"]{1,2000})"""
      """"rule.description":"({description}[^"]{1,2000})"""
      """"decoder.name":"({decoder_name}[^"]{1,2000})"""
      """"rule.id":"({rule_id}\d{1,100})"""
      """"agent.name":"({agent_name}[^"]{1,2000})"""
      """"agent.id":"({agent_id}[^"]{1,2000})"""
      """"data.status":"({outcome}[^"]{1,2000})"""
      """({app}Ping)"""
      """"data.link2":"({app}[^"]{1,2000})"""
      """"data.type":"({additional_info}[^"]{1,2000})"""
    ]
    DupFields = [ "description->event_name" ] 
  } 
  wazuh-common-fields {
    Lms = Direct
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """"@timestamp":"({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)"""
      """"location":"({log_location}[^"]{1,2000})"""
      """"path":"({log_path}[^"]{1,2000})"""
      """"agent.id":"({agent_id}\d{1,100})"""
      """"manager.name":"({wazuh_manager}[^"]{1,2000})"""
      """"rule.description":"({description}[^"]{1,2000})"""
      """"decoder.name":"({decoder_name}[^"]{1,2000})"""
      """"rule.id":"({rule_id}\d{1,100})"""
      """"agent.name":"({agent_name}[^"]{1,2000})"""
      """"agent.id":"({agent_id}[^"]{1,2000})"""
    
}
```