#### Parser Content
```Java
{
Name = azure-atp-security-alert-7
Vendor = Microsoft
Product = Azure Advanced Threat Protection
Lms = Splunk
DataType = "alert"
TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
Conditions = [ """CEF:""", """destinationServiceName =Azure""", """cat=security-alert""", """"category":""", """"title":""", """"vendor":""", """"Microsoft"""", """"provider":"Azure Advanced Threat Protection""" ]
Fields = [
""""eventDateTime":"({time}\d{4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{1,2}\.\d{1,6}Z)"""
"""act=({action}[^\s]{1,2000})"""
""""hostStates":\[\{"fqdn":"({host}[\w\-.]{1,2000})"""
""""category":"({alert_type}[^"]{1,2000})"""
""""logonIp":({src_ip}[A-fa-f\d:.]{1,2000})"""
""""netBiosName":"(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9]{1,2000}:[A-Fa-f0-9:]{1,2000}))|({src_host}[\w\-.]{1,2000}))"""
"""domainName":((?i)null|({domain}"[^,]{1,2000}))"""
""""description":"({additional_info}[^"]{1,2000})"""
""""severity":"({alert_severity}[^"]{1,2000})"""
""""id":"({alert_id}[^"]{1,2000})"""
""""sourceMaterials":\["({malware_url}[^"]{1,2000})"""
""""title":"({alert_name}[^"]{1,2000})"""
""""userPrincipalName":"((?i)null|(({user_fullname}[^\s"]{1,2000}\s{1,20}[^"]{1,2000})|({user}[^"]{1,2000})))"""
""""userPrincipalName":"((?i)null|({user_email}[^\@"]{1,2000}\@([^\."]{1,2000}\.){0,20}\w{1,2000}))"""
""""logonLocation":((?i)null|({src_location}[^"]{1,2000}))"""
]


}
```