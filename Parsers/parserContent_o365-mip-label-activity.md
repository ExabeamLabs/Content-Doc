#### Parser Content
```Java
{
Name = o365-mip-label-activity
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """Workload""", """"LabelName"""", """"LabelId""", """Operation""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """"*CreationTime"*:\s*"*({time}\d+-\d+-\d+T\d+:\d+:\d+)"*""",
    """Workload"*:\s*"*({app}[^"]+)"""",
    """ObjectId"*:\s*"*<?({object}[^"]+?)>?"""",
    """Operation"*:\s*"*({activity}[^"]+)"*""",
    """UserId"*:\s*"*({user_email}[^@]+@({email_domain}[^"]+))"*""",
    """Sender"*:\s*"*({sender}[^"]+)"""",
    """Receivers"*:\s*\["*({recipient}[^"]+)"""
    ]
    DupFields = [ "sender->user_email", "recipient->recipients" ]
}
{
  Name = o365-dlp-policy-alert
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """Workload""", """"RuleName"""", """"PolicyDetails"""", """Operation""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """"*CreationTime"*:\s*"*({time}\d+-\d+-\d+T\d+:\d+:\d+)"*""",
    """Workload"*:\s*"*({app}[^"]+)"""",
    """ObjectId"*:\s*"*<?({object}[^"]+?)>?"""",
    """Operation"*:\s*"*({activity}[^"]+)"*""",
    """UserId"*:\s*"*({user_email}[^@]+@({email_domain}[^"]+))"*""",
    """FileSize"*:\s*"*({bytes}\d+)""",
    """From"*:\s*"*({sender}[^"]+)"""",
    """To"*:\s*\["*({recipient}[^"]+)""",
    """Subject"*:\s*"*({subject}[^"]+?)\s*"""",
    """MessageID"*:\s*"*<?({message_id}[^"]+?)>?"""",
    """Severity"*:\s*"*({alert_severity}[^"]+)"""",
    """IncidentId"*:\s*"*({alert_id}[^"]+)"""",
    """Actions"*:\s*\["*({outcome}[^"\]]+?)\s*"""",
    """RuleName"*:\s*"*(|({alert_name}.+?[^"]))"""",
    """FileName"*:\s*"*(|({file_name}.+?[^"]))"""",
    """RecipientCount"*:\s*({recipient_count}\d+)"""
    ]
    DupFields = [ "sender->user_email", "recipient->recipients" ]
}
{
  Name = azure-file-read
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Splunk
  DataType = "file-read"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """|resource-viewed|""","""|Skyformation|""","""destinationServiceName=Azure""" ]
  Fields = [
   """({time}\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)""",
   """"ResourceProvider":"({object}[^"]+)""",
   """"ResourceId":"({file_path}({file_parent}(?:[^";]+)?[\/;])?({file_name}[^\/";]+))""""
   """"Resource":"({file_name}[^"]+)"""",
   """suser=((?i)anonymous|({user}[^\s]+))""",
   """devicePayloadId=.+\s+name\s+:\s+\[({host}[^\]]+)"""
   """fileType=({file_type}[^\s]+)""",
   """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
   """"ResultType":"({outcome}[^"]+)""",
   """requestClientApplication=({app}.+?)\s\w+=""",
   """"OperationName":"({event_name}[^"]+)"""",
   """({accesses}resource-viewed)"""
   """msg=({additional_info}.+?)\s+\w+="""
  ]
}

{
  Name = azure-file-write
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Splunk
  DataType = "file-write"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """|Skyformation|""", """|sk4-resource-created|""", """|SkyFormation Cloud Apps Security|""", """destinationServiceName=Azure""" ]
  Fields = [
   """({time}\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)""",
   """"ResourceProvider":"({object}[^"]+)""",
   """"ResourceId":"({file_path}({file_parent}(?:[^";]+)?[\/;])?({file_name}[^\/";]+))""""
   """"Resource":"({file_name}[^"]+)"""",
   """suser=((?i)anonymous|({user}[^\s]+))""",
   """devicePayloadId=.+\s+name\s+:\s+\[({host}[^\]]+)"""
   """fileType=({file_type}[^\s]+)""",
   """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
   """"ResultType":"({outcome}[^"]+)""",
   """requestClientApplication=({app}.+?)\s\w+=""",
   """"OperationName":"({event_name}[^"]+)"""",
   """({accesses}resource-created)"""
   """msg=({additional_info}.+?)\s+\w+="""
  ]
}

{
  Name = azure-event-hub-application-gateway-firewall-log
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [""""category":"ApplicationGatewayFirewallLog"""","""CEF:""", """|SkyFormation Cloud Apps Security|""" ]
  Fields =[
    """\s({time}\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)\s""",
    """"clientIp":"({src_ip}[^"]+)""",
    """"clientPort":"({src_port}[^"]+)""",
    """"requestUri":"({request_uri}[^"]+)""",
    """"ruleSetType":"({rule}[^"]+)""",
    """"ruleId":"({rule_id}[^"]+)""",
    """"ruleGroup.+?"message":"({additional_info}[^"]+)""",
    """"action":"({outcome}[^"]+)""",
    """"hostname":"({host}[^"]+)""",
    """"transactionId":"({transaction_id}[^"]+)""",
    """"file":"({file_path}({file_parent}[^\/"]+)\/({file_name}[^"]+))""",
    """\[Namespace:\s*({azure_event_hub_namespace}\S+) ; EventHub name:\s*({azure_event_hub_name}[\w-]+)""",
  ]
}

{
  Name = azure-event-hub-app-service-audit-logs
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Azure""","""Category":"AppServiceAuditLogs""" ]
  Fields = [
    """"time"+:"+({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{7}\w+)"""",
    """\s\d+-\d+-\d+T\d+:\d+:\d+\.\d+\w+\s({host}[^\s]+)"""
    """destinationServiceName=({app}[^\s]+)""",
    """"Category":"({category}[^"]+)""",
    """suser=(anonymous|({user}.+?))\s+\w+="""
    """"ResourceId":"({object}[^"]+)"""",
    """"OperationName":"({activity}[^"]+)""",
    """"User":"({user}[^"]+)"""",
    """"UserDisplayName":"({user_email}[^@]+@[^\.]+\.[^"]+)"""",
    """"UserAddress":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"Protocol":"({protocol}[^"]+)"""",
    """\[Namespace:\s*({azure_event_hub_namespace}\S+) ; EventHub name:\s*({azure_event_hub_name}[\w-]+)"""
  ]
}
```