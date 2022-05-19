#### Parser Content
```Java
{
Name = wazuh-4673
  DataType = "windows-privileged-access"
  Conditions = [ """"data.id":"4673"""", """wazuh-alerts""", """"decoder.parent":"windows""""  ]
  Fields = ${WazuhParserTemplates.wazuh-windows-template.Fields} [
    """({event_name}A privileged service was called)""",
    """"full_log":".*?\s{0,100}Source Address:\s{0,100}(?:-|({src_ip}[^\s]{1,2000}))\s{0,100}Source Port:"""
    """"full_log":".*?Process Name:\s{0,100}(?: |({process}({directory}(?:[^"]{0,2000}?)[\\\/]{1,2000})?({process_name}[^\\\/":]{1,2000}?)))\s{0,100}Service Request Information:"""
    """"full_log":".*?\s{0,100}Account Name:\s{0,100}({user}.+?)\s{0,100}Account Domain:"""
    """"full_log":".*?\s{0,100}Account Domain:\s{0,100}({domain}.+?)\s{0,100}Logon ID:"""
    """"full_log":".*?\s{0,100}Logon ID:\s{0,100}({logon_id}.+?)\s{0,100}Service:"""
    """"full_log":".*?\s{0,100}Server:\s{0,100}({object_server}[^:]{1,2000}?)\s{0,100}Service Name"""
    """"full_log":".*?\s{0,100}Privileges:\s{0,100}({privileges}.+?)(\s{1,100}\d{1,100}|\"|,)"""
  ]
  DupFields = ["directory->process_directory"]

wazuh-windows-template = {
    Vendor = Microsoft
    Product = Windows
    Lms = Direct
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """"data.id":"({event_code}\d{1,100})""""
      """"@timestamp":"({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)"""
      """"data.dstuser":"(\(no user\)|({dest_user}[^"]{1,2000}))"""
      """"data.status":"({outcome}[^"]{1,2000})"""
      """"location":"({log_location}[^"]{1,2000})"""
      """"data.data":"({data}[^"]{1,2000})"""
      """"path":"({log_path}[^"]{1,2000})"""
      """"data.system_name":"({host}[^"]{1,2000})"""
      """"agent.id":"({agent_id}\d{1,100})"""
      """"manager.name":"({wazuh_manager}[^"]{1,2000})"""
      """"data.data":"({data}[^"]{1,2000})"""
      """"rule.description":"({description}[^"]{1,2000})"""
      """"decoder.name":"({decoder_name}[^"]{1,2000})"""
    
}
```