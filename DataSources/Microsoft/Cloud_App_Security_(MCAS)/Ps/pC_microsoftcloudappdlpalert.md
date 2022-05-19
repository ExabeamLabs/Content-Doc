#### Parser Content
```Java
{
Name = microsoft-cloud-app-dlp-alert
  Product = Cloud App Security (MCAS)
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Conditions = [ """"category":""", """"MCAS_ALERT_CABINET_EVENT_MATCH_FILE"""", """"title":""", """"vendor":""", """"Microsoft"""", """"provider":""", """"MCAS""""  ]

json-microsoft-security-events = {
     Vendor = Microsoft
     Lms = Splunk
     TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
     Fields = [
     """exabeam_host=([^=]{1,2000}@\s{0,100})?(::ffff:)?({host}\S{1,2000})""",
     """"id":\s{0,100}"({alert_id}[^"]{1,2000})"""",
     """"title":\s{0,100}"({alert_name}[^"]{1,2000})"""",
     """"severity":\s{0,100}"({alert_severity}[^"]{1,2000})"""",
     """"category":\s{0,100}"({alert_type}[^"]{1,2000})"""",
     """"description":\s{0,100}"({additional_info}[^}\]]{1,2000}?)\s{0,100}"[,\]}]""",
     """"eventDateTime":\s{0,100}"({time}[^"]{1,2000})"""",
     """"accountName":\s{0,100}"(-|({user_fullname}[^"\s]{1,2000}\s[^"]{1,2000})|({user_email}[^"@]{1,2000}@[^"]{1,2000})|({user}[^\s"]{1,2000}))"""",
     """aadUserId[^}\]]{1,2000}?"accountName":\s{0,100}"(-|({user_fullname}[^"\s]{1,2000}\s[^"]{1,2000})|({user_email}[^"@]{1,2000}@[^"]{1,2000})|({user}[^\s"]{1,2000}))"""",
     """"logonIp":\s{0,100}"({src_ip}[a-fA-F:\d.]{1,2000})"""",
     """"userPrincipalName":\s{0,100}"(-|({user_email}[^@"]{1,2000}@[^".]{1,2000}\.[^"]{1,2000})|(({user}[^\s"@]{1,2000})(@[^"]{1,2000})?))"""",
     """"userPrincipalName":\s{0,100}"({user_upn}[^"]{1,2000}?)"""",
     """"domainName"{1,20}:\s{0,100}"{1,20}(-|({domain}[^"]{1,2000}))"""",
     """"domainName"{1,20}:\s{0,100}"{1,20}(-|({domain}[^"]{1,2000}))[^}\]]{1,2000}?userPrincipalName""",
     """"fqdn"{1,20}:\s{0,100}"{1,20}({src_host}[^"]{1,2000})"""",
     """"{1,20}hostStates"{1,20}:[^}\]]{1,2000}?privateIpAddress"{1,20}:\s{0,100}"{1,20}({src_ip}[a-fA-F:\d.]{1,2000})""",
     """"{1,20}hostStates"{1,20}:[^}\]]{1,2000}?publicIpAddress"{1,20}:\s{0,100}"{1,20}({dest_ip}[a-fA-F:\d.]{1,2000})""",
     """"description":\s{0,100}"An actor on\s{0,100}({src_host}\S{1,2000})\s{0,100}performed suspicious""",
     """"fileStates":[^]]{1,2000}?"name":\s{0,100}"({file_name}[^."]{1,2000}([\.\w]{1,100})?)""""
     
}
```