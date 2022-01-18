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
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
      """activityDateTime": "({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""
      """({service}Core Directory)""",
      """result": "({outcome}[^"]{1,2000})""",
      """activityDisplayName": "({activity}[^"]{1,2000})""",
      """resultReason": "({failure_reason}[^"]{1,2000})""",
      """initiatedBy.+?"user".+?"id"{1,20}:\s{0,100}"{1,20}({user}[^"]{1,2000})""""
      """initiatedBy.+?"user".+?"userPrincipalName"{1,20}:\s{0,100}"{1,20}({user_email}[^"@]{1,2000}@[^"]{1,2000})""""
      """additionalDetails.+?User-Agent"{1,20

}
```