#### Parser Content
```Java
{
Name = wazuh-sql-login
  DataType = "app-login"
  Conditions = [ """"type":"wazuh-alerts"""", """"rule.description":"MS SQL Server Logon"""  ]
  Fields = ${WazuhParserTemplates.wazuh-windows-template.Fields} [
    """Login succeeded for user '(({domain}[^\\:]{1,2000})\\+)?({user}[\w.'\-\\$]{1,2000})'"""
    """({app}SQL Server)"""
    """"rule.description":"MS SQL Server Logon ({outcome}(Success|Failure)).""""
  ]

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