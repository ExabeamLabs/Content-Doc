#### Parser Content
```Java
{
Name = s-azure-managed-identity
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Splunk
  DataType = "cloud-admin-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""operationName":"MICROSOFT.MANAGEDIDENTITY"""]
  Fields = [
     """time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""
     """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
     """({service}MICROSOFT.MANAGEDIDENTITY)""",
     """"MICROSOFT.MANAGEDIDENTITY\/({activity}[^"]+)""",
     """ipaddr":"({src_ip}[^"]+)""",
     """callerIpAddress":"({src_ip}[^"]+)""",
     """surname":"({user_lastname}[^"]+)""",
     """givenname":"({user_firstname}[^"]+)""",
     """claims\/name":"({user_email}[^@]+@[^"]+)""",
     """identity/claims/nameidentifier":"({user}[^"]+)"""
     """roleDefinitionId":"({role}[^"]+)""",
     """Microsoft.Authorization/policyDefinitions/({policy}[^\/\\"]+)""",
     """resultType":"({outcome}[^"]+)"""
     """resourceId":".*\/RESOURCEGROUPS\/({account_id}[^\/]+)"""
         """\[Namespace:\s{0,100}({event_hub_namespace}\S+) ; EventHub name:\s{0,100}({event_hub_name}[\w-]+)"""
   ]
DupFields= ["event_hub_namespace->host"]
}
```