#### Parser Content
```Java
{
Name = wazuh-ssh-login
  Product = Unix
  Conditions = [ """"decoder.parent":"sshd"""", "Accepted ", " for ", " from ", """"type":"wazuh-alerts"""" ]
  Fields = ${WazuhParserTemplates.wazuh-ssh-login.Fields} [
    """sshd\[.+?Accepted ({auth}\S+) for (({domain}[^\\:]{1,2000})\\+)?({user}[\w.'\-\\$]{1,2000})"""
  ]

wazuh-ssh-login {
    Vendor = Unix
    Lms = Direct
    DataType = "ssh-login"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """"predecoder.hostname":"({host}[^"]{1,2000})"""
      """\s({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\.-]{1,2000})\s{1,100}sshd\[""",
      """\s({host}[\w\.-]{1,2000})\s{1,100}sshd\[""",
      """sshd\[({logon_id}\d{1,100})""",
      """({event_code}ssh)""",
      """\s{1,100}port\s{1,100}({src_port}\d{1,100})""",
      """"@timestamp":"({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)"""
      """"data.dstuser":"(\(no user\)|({dest_user}({user}[^"]{1,2000})))"""
      """"location":"({log_location}[^"]{1,2000})"""
      """"path":"({log_path}[^"]{1,2000})"""
      """"agent.id":"({agent_id}\d{1,100})"""
      """"manager.name":"({wazuh_manager}[^"]{1,2000})"""
      """"rule.description":"({description}[^"]{1,2000})"""
      """"decoder.name":"({decoder_name}({process_name}[^"]{1,2000}))"""
      """"rule.id":"({rule_id}\d{1,100})"""
      """"agent.name":"({agent_name}[^"]{1,2000})"""
      """"agent.id":"({agent_id}[^"]{1,2000})"""
      """"data.srcip":"({src_ip}[:0-9a-fA-F\.]{1,2000})"""
    ]
    DupFields = ["dest_host->original_dest_host", "description->event_name"
}
```