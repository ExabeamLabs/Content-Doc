#### Parser Content
```Java
{
Name = s-azure-authorization-activity-2
 Vendor = Microsoft
 Product = Microsoft Azure
 Lms = Splunk
 DataType = "cloud-admin-activity"
 TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
 Conditions = ["""operationName":"MICROSOFT.AUTHORIZATION"""]
 Fields = [
         """time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
         """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
         """({service}MICROSOFT.AUTHORIZATION)""",
         """"MICROSOFT.AUTHORIZATION\/[^\/]+\/({activity}[^\/"]+)""",
         """"MICROSOFT.AUTHORIZATION\/({activity}[^"]+)"""
         """ipaddr":"({src_ip}[^"]+)""",
         """callerIpAddress":"({src_ip}[^"]+)""",
         """surname":"({user_lastname}[^"]+)""",
         """givenname":"({user_firstname}[^"]+)""",
         """claims\/name":"({user_email}[^@]+@[^"]+)""",
         """identity/claims/nameidentifier":"({user}[^"]+)""",
         """roleDefinitionId":"({role}[^"]+)""",
         """resourceId":".*\/RESOURCEGROUPS\/({account_id}[^\/]+)"""
         """Microsoft.Authorization/policyDefinitions/({policy}[^\/\\"]+)""",
         """resultType":"({outcome}[^"]+)""",
         """\[Namespace:\s*({event_hub_namespace}\S+) ; EventHub name:\s*({event_hub_name}[\w-]+)"""
 ]
DupFields= ["event_hub_namespace->host"]
}
```