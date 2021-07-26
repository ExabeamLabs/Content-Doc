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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"time"{1,20}:"{1,20}({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{7}\w+)"""",
    """destinationServiceName=({app}[^\s]{1,2000})""",
    """"Category":"({category}[^"]{1,2000})""",
    """suser=(anonymous|({user}[^=]{1,2000}))\s{1,100}\w+="""
    """"ResourceId":"({object}[^"]{1,2000})"""",
    """"OperationName":"({activity}[^"]{1,2000})""",
    """"User":"({user}[^"]{1,2000})"""",
    """"UserDisplayName":"({user_email}[^@]{1,2000}@[^\.]{1,2000}\.[^"]{1,2000})"""",
    """"UserAddress":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"Protocol":"({protocol}[^"]{1,2000})"""",
    """\[Namespace:\s{0,100}({event_hub_namespace}\S+) ; EventHub name:\s{0,100}({event_hub_name}[\w-]{1,2000})""",
  
  ]

  DupFields= ["event_hub_namespace->host"]
}
```