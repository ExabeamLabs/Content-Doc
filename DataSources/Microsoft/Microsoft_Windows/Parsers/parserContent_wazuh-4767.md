#### Parser Content
```Java
{
Name = wazuh-4767
  DataType = "windows-account-unlocked"
  Conditions = [ """"data.id":"4767"""", """"type":"wazuh-alerts"""", """"decoder.parent":"windows""""  ]
  Fields = ${WazuhParserTemplates.wazuh-windows-template.Fields} [
    """({event_name}A user account was unlocked)""",
    """({time}\w+ \d\d \d\d:\d\d:\d\d \d\d\d\d)\s{1,100}""",
    """Subject:.+?Account Name:\s{0,100}({user}.+?)\s{0,100}Account Domain:\s{0,100}({domain}.+?)\s{0,100}Logon ID:\s{0,100}({logon_id}.+?)\s{0,100}Target Account:""",
    """Target Account:\s{0,100}Security ID:\s{0,100}({user_sid}.+?)\s{0,100}Account Name:\s{0,100}({target_user}.+?)\s{0,100}Account Domain:\s{0,100}({target_domain}[^\s"]+)"""
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