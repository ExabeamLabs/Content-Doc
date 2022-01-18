#### Parser Content
```Java
{
Name = wazuh-4738
  DataType = "account-modification"
  Conditions = [ """"data.id":"4738"""", """"type":"wazuh-alerts"""", """"decoder.parent":"windows""""  ]
  Fields = ${WazuhParserTemplates.wazuh-windows-template.Fields} [
    """({event_name}A user account was changed)""",
    """Security ID:\s{0,100}(|({user_sid}.+?))\s{1,100}Account Name:""",
    """Account Name:\s{0,100}(|({user}.+?))\s{1,100}Account Domain:\s{0,100}(|({domain}.+?))\s{1,100}Logon ID:\s{0,100}(|({logon_id}.+?))\s{1,100}Target Account:""",
    """Target\sAccount.+?Security ID:\s{0,100}({target_sid}.+?)\s""",
    """Target\sAccount.+?Account Name:\s{0,100}({target_user}.+?)\s""",
    """Target\sAccount.+?Account Domain:\s{0,100}({target_domain}.+?)\s""",
    """Changed Attributes:\s{0,100}(|({attribute}.+?))\s{1,100}SAM Account Name"""
  ]

wazuh-windows-template = {
    Vendor = Microsoft
    Product = Microsoft Windows
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