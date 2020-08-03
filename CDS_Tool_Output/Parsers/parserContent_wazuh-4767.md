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
```