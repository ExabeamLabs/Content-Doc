#### Parser Content
```Java
{
Name = wazuh-unix-sudo
  Product = Unix
  Conditions = [ """"decoder.parent":"sudo"""", """"type":"wazuh-alerts"""" ]

wazuh-unix-sudo-template {
    Vendor = Unix
    Lms = Direct
    DataType = "unix-account-switch"
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
      """"data.srcuser":"({user}[^"]{1,2000})"""
      """"data.pwd":"({directory}[^"]{1,2000})"""
      """"data.command":"({process}([^\s]{1,2000}[\\\/]{1,2000})?({process_name}[^;\\\/\s]{1,2000}))""" 
      """"data.command":"({command_line}[^;"]{1,2000})"""
      """"cluster.name":"({cluster_name}[^"]{1,2000})"""
      """"host":"({wazuh_manager}[^"]{1,2000})"""
      """"rule.level":"({level}[^"]{1,2000})"""
      """"rule.level":({level}\d{1,100}),"""
      """"predecoder.hostname":"({host}[^"]{1,2000})""" 
    ]
    DupFields = ["description->event_name", "dest_user->account"
}
```