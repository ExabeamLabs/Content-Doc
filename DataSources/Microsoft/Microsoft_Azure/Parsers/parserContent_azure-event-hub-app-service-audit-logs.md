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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"time"{1,20}:"{1,20}({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{7}\w+)"""",
    """destinationServiceName=({app}[^\s]+)""",
    """"Category":"({category}[^"]+)""",
    """suser=(anonymous|({user}[^=]+))\s{1,100}\w+="""
    """"ResourceId":"({object}[^"]+)"""",
    """"OperationName":"({activity}[^"]+)""",
    """"User":"({user}[^"]+)"""",
    """"UserDisplayName":"({user_email}[^@]+@[^\.]+\.[^"]+)"""",
    """"UserAddress":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"Protocol":"({protocol}[^"]+)"""",
    """\[Namespace:\s{0,100}({event_hub_namespace}\S+) ; EventHub name:\s{0,100}({event_hub_name}[\w-]+)""",
  
  ]

  DupFields= ["event_hub_namespace->host"]
}
```