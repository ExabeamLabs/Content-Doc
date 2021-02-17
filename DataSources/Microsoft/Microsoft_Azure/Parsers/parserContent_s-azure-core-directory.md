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
      """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
      """activityDateTime": "({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""
      """({service}Core Directory)""",
      """result": "({outcome}[^"]+)""",
      """activityDisplayName": "({activity}[^"]+)""",
      """resultReason": "({failure_reason}[^"]+)""",
      """initiatedBy.+?"user".+?"id"+:\s*"+({user}[^"]+)""""
      """initiatedBy.+?"user".+?"userPrincipalName"+:\s*"+({user_email}[^"@]+@[^"]+)""""
      """additionalDetails.+?User-Agent"+, "+value"+: "+({user_agent}[^"]+)"""
   ]
}
```