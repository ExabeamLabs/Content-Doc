#### Parser Content
```Java
{
Name = s-azure-api-management
 Vendor = Microsoft
 Product = Microsoft Azure
 Lms = Splunk
 DataType = "cloud-admin-activity"
 TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
 Conditions = ["""operationName":"MICROSOFT.APIMANAGEMENT"""]
 Fields = [
         """time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
         """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
         """({service}MICROSOFT.APIMANAGEMENT)""",
         """"MICROSOFT.APIMANAGEMENT\/({activity}[^"]+)""",
         """ipaddr":"({src_ip}[^"]+)""",
         """callerIpAddress":"({src_ip}[^"]+)""",
         """surname":"({user_lastname}[^"]+)""",
         """givenname":"({user_firstname}[^"]+)""",
         """claims\/name":"({user_email}[^@]+@[^"]+)""",
         """identity/claims/nameidentifier":"({user}[^"]+)""",
         """roleDefinitionId":"({role}[^"]+)""",
         """resourceId":".*\/RESOURCEGROUPS\/({account_id}[^\/]+)"""
         """resultType":"({outcome}[^"]+)""",
         """\[Namespace:\s*({event_hub_namespace}\S+) ; EventHub name:\s*({event_hub_name}[\w-]+)"""
 ]
DupFields= ["event_hub_namespace->host"]
}
```