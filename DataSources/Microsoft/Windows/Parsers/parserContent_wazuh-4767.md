#### Parser Content
```Java
{
Name = wazuh-4767
  DataType = "windows-account-unlocked"
  Conditions = [ """"data.id":"4767"""", """"type":"wazuh-alerts"""", """"decoder.parent":"windows""""  ]
  Fields = ${WazuhParserTemplates.wazuh-windows-template.Fields} [
    """({event_name}A user account was unlocked)""",
    """({time}\w+ \d\d \d\d:\d\d:\d\d \d\d\d\d)\s+""",
    """Subject:.+?Account Name:\s*({user}.+?)\s*Account Domain:\s*({domain}.+?)\s*Logon ID:\s*({logon_id}.+?)\s*Target Account:""",
    """Target Account:\s*Security ID:\s*({user_sid}.+?)\s*Account Name:\s*({target_user}.+?)\s*Account Domain:\s*({target_domain}[^\s"]+)"""
  ]
}
wazuh-windows-template = {
    Vendor = Microsoft
    Product = Windows
    Lms = Direct
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """"data.id":"({event_code}\d+)""""
      """"@timestamp":"({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)"""
      """"data.dstuser":"(\(no user\)|({dest_user}[^"]+))"""
      """"data.status":"({outcome}[^"]+)"""
      """"location":"({log_location}[^"]+)"""
      """"data.data":"({data}[^"]+)"""
      """"path":"({log_path}[^"]+)"""
      """"data.system_name":"({host}[^"]+)"""
      """"agent.id":"({agent_id}\d+)"""
      """"manager.name":"({wazuh_manager}[^"]+)"""
      """"data.data":"({data}[^"]+)"""
      """"rule.description":"({description}[^"]+)"""
      """"decoder.name":"({decoder_name}[^"]+)"""
    ]

```