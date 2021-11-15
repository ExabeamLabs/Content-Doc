#### Parser Content
```Java
{
Name = wazuh-unix-su
  Product = Unix
  Vendor = Unix
  DataType = "unix-account-switch"
  Conditions = [ """"type":"wazuh-alerts"""", "session opened for user","su:", """(uid=""" ]
  Fields = ${WazuhParserTemplates.wazuh-common-fields.Fields} [
    """"predecoder.hostname":"({host}[^"]{1,2000})""",
    """({event_code}su)""",
    """"data.dstuser":"({account}[^"]{1,2000})""",
    """"data.srcuser":"({user}[^"]{1,2000})""",
    """"data.uid":"({user_uid}[^"]{1,2000})"""
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