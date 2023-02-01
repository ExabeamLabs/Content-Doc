#### Parser Content
```Java
{
Name = s-azure-container-service
 Vendor = Microsoft
 Product = Azure
 Lms = Splunk
 DataType = "cloud-admin-activity"
 TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
 Conditions = [ """destinationServiceName =Azure""", """"operationName":"Microsoft.ContainerService""", """"category":"kube-audit-admin"""" ]
 Fields = [
         """"time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
         """({service}Microsoft.ContainerService)""",
         """"Microsoft.ContainerService\/({activity}[^"]{1,2000})""",
         """"user":\{"username":"({user}[^"]{1,2000})"""",
         """"sourceIPs":\["({src_ip}[^"]{1,2000})""",
         """"userAgent":"({user_agent}[^"]{1,2000})""",
         """"operation":"({action}[^"]{1,2000})"""",
         """"roleDefinitionId":"({role}[^"]{1,2000})""",
         """"resourceId":".*\/RESOURCEGROUPS\/({account_id}[^\/]{1,2000})""", 
         """\[Namespace:\s{0,100}({event_hub_namespace}\S+) ; EventHub name:\s{0,100}({event_hub_name}[\w-]{1,2000})"""
 ]
 DupFields= ["event_hub_namespace->host"]


}
```