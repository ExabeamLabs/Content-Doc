#### Parser Content
```Java
{
Name = wazuh-4776
  DataType = "windows-4776"
  Conditions = [ """"data.id":"4776"""", """"type":"wazuh-alerts"""", """"decoder.parent":"windows""""  ]
  Fields = ${WazuhParserTemplates.wazuh-windows-template.Fields} [
    """({event_name}The (computer|domain controller) attempted to validate the credentials for an account)"""
      """The ({login_type}computer|domain)(\s\w+)? attempted to validate the credentials"""
      """Logon (?:a|A)ccount:(?:\s+Source Workstation|\s*({user}[^\s@]+?)(?:@({domain}[^\s.]+).*?)?\s*Source Workstation)"""
      """Error Code:\s*({result_code}[\w\-]+)"""
      """Source Workstation:\s*\\*(?:\s+Error Code:|(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*Error Code:)|(\s*({dest_host}[^\s]+?)\s*Error Code:))\s*""" 
  ]
}
```