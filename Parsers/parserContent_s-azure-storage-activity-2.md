#### Parser Content
```Java
{
Name = s-azure-storage-activity-2
 Vendor = Microsoft
 Product = Microsoft Azure
 Lms = Splunk
 DataType = "cloud-storage-access"
 TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
 Conditions = ["""operationName":"MICROSOFT.STORAGE"""]
 Fields = [
         """time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
         """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
         """({service}MICROSOFT.STORAGE)""",
         """"MICROSOFT.STORAGE\/[^\/]+\/({activity}[^\/"]+)""",
         """operationName":"MICROSOFT.STORAGE.+?\/CONTAINERS\/({activity}[["\\\/]+)""",
         """resourceId":".+?DEFAULT\/CONTAINERS\/({bucket}[^\\\/"]+)""",
         """operationName":".+?({activity}FILESERVICES\/\w+)""",
         """operationName":"MICROSOFT.STORAGE/({activity}STORAGEACCOUNTS\/[^"]+)""",
         """ipaddr":"({src_ip}[^"]+)""",
         """callerIpAddress":"({src_ip}[^"]+)""",
         """surname":"({user_lastname}[^"]+)""",
         """givenname":"({user_firstname}[^"]+)""",
         """claims\/name":"({user_email}[^@]+@[^"]+)""",
         """identity/claims/nameidentifier":"({user}[^"]+)""",
         """"Microsoft.Storage\/storageAccounts\/({resource}[^"\/\\]+).*"action"""",
         """roleDefinitionId":"({role}[^"]+)""",
         """"Microsoft.Authorization/policyDefinitions/({policy}[^\/\\"]+)""",
         """resultType":"({outcome}[^"]+)""",
         """resourceId":".*\/RESOURCEGROUPS\/({account_id}[^\/]+)""",
         """\[Namespace:\s*({event_hub_namespace}\S+) ; EventHub name:\s*({event_hub_name}[\w-]+)"""
 ]
DupFields= ["event_hub_namespace->host"]
}
```