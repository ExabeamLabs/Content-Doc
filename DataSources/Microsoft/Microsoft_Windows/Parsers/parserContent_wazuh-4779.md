#### Parser Content
```Java
{
Name = wazuh-4779
  DataType = "windows-4779"
  Conditions = [ """"data.id":"4779"""", """"type":"wazuh-alerts"""", """"decoder.parent":"windows""""  ]
  Fields = ${WazuhParserTemplates.wazuh-windows-template.Fields} [
    """({event_name}A session was disconnected from a Window Station)""",
    """Account Name:\s{0,100}({user}\S+)\s{1,100}Account Domain:""",
    """Account Domain:\s{0,100}({domain}\S+)\s{1,100}Logon ID:""",
    """Logon ID:\s{0,100}({logon_id}\S+)""",
    """Service Name:\s{0,100}({dest_host}.+?)\s{0,100}Service ID""",
    """Client Address:\s{0,100}(::[\w]+:)?({src_ip}[a-fA-F:\d.]+)""",  
  ]
}
wazuh-windows-template = {
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """"data.id":"({event_code}\d{1,100})""""
      """"@timestamp":"({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)"""
      """"data.dstuser":"(\(no user\)|({dest_user}[^"]+))"""
      """"data.status":"({outcome}[^"]+)"""
      """"location":"({log_location}[^"]+)"""
      """"data.data":"({data}[^"]+)"""
      """"path":"({log_path}[^"]+)"""
      """"data.system_name":"({host}[^"]+)"""
      """"agent.id":"({agent_id}\d{1,100})"""
      """"manager.name":"({wazuh_manager}[^"]+)"""
      """"data.data":"({data}[^"]+)"""
      """"rule.description":"({description}[^"]+)"""
      """"decoder.name":"({decoder_name}[^"]+)"""
    ]

```