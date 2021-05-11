#### Parser Content
```Java
{
Name = s-azure-core-directory
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Splunk
  DataType = "cloud-admin-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""loggedByService": "Core Directory""", """activityDisplayName"""]
  Fields = [
      """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
      """activityDateTime": "({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""
      """({service}Core Directory)""",
      """result": "({outcome}[^"]+)""",
      """activityDisplayName": "({activity}[^"]+)""",
      """resultReason": "({failure_reason}[^"]+)""",
      """initiatedBy.+?"user".+?"id"{1,20}:\s{0,100}"{1,20}({user}[^"]+)""""
      """initiatedBy.+?"user".+?"userPrincipalName"{1,20}:\s{0,100}"{1,20}({user_email}[^"@]+@[^"]+)""""
      """additionalDetails.+?User-Agent"{1,20}
```