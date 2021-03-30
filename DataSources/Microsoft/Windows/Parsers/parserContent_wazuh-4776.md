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