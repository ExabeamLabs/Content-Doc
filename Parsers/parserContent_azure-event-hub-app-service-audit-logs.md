#### Parser Content
```Java
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