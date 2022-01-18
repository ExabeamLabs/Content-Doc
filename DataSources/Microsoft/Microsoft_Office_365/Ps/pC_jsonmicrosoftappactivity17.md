#### Parser Content
```Java
{
Name = json-microsoft-app-activity-17
  Product = Microsoft Office 365
  Conditions= [ """"Operation":"FileModified"""", """"Workload":"""", """"SourceFileName":"""" ]

json-microsoft-app-activity = {
  Vendor = Microsoft
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"activityDate":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"activity":"({activity}[^"]{1,2000})"""",
    """"(ipAddress|FromIP|ClientIP)":"({src_ip}[^"]{1,2000})"""",
    """"(UserId|userPrincipalName)":"({user_email}[^@]{1,2000}@({email_domain}[^"]{1,2000}))"""",
    """"activityResultStatus":"({status}[^"]{1,2000})"""",
    """"category":"({category}[^"]{1,2000})"""",
    """"source":"({log_source}[^"]{1,2000})"""",
    """"activityType":"({object_type}[^"]{1,2000})"""",
    """"id":"({object_id}[^"]{1,2000})"""",
    """"correlationId":"({conn_id}[^"]{1,2000})"""",
    """\WdestinationServiceName\s{0,100}=({app}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\WsourceServiceName =({app}[^=]{1,2000}?)\s{1,100}(\w+=|$)"""
  ]
  DupFields = [ "object->resource" 
}
```