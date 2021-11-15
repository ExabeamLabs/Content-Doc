#### Parser Content
```Java
{
Name = wazuh-unix-password-change
  Product = Unix
  Vendor = Unix
  DataType = "password-change"
  Conditions = [ """"type":"wazuh-alerts"""", """"rule.description":"PAM: User changed password."""" ]
  Fields = ${WazuhParserTemplates.wazuh-common-fields.Fields} [
    """"predecoder.hostname":"({host}[^"]{1,2000})""",
    """"data.dstuser":"({target_user}[^"]{1,2000})""",
    """"agent\.labels\.network\.ipv4\.primary":"({src_ip}(\d{1,3}\.){3}\d{1,3})"""
]
  DupFields=["host->dest_host", "description->event_name"]

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