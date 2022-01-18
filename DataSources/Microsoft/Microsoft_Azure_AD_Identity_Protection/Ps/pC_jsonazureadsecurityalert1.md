#### Parser Content
```Java
{
Name = json-azure-ad-security-alert-1
  Vendor = Microsoft
  Product = Microsoft Azure AD Identity Protection
  Lms = Splunk
  DataType = "security-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Conditions = [ """"category": "ImpossibleTravel"""", """"title": """, """"vendor": "Microsoft"""", """"provider": "IPC"""" ]
  Fields = [
     """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
     """"id":\s{0,100}"({alert_id}[^"]{1,2000})"""",
     """"title":\s{0,100}"({alert_name}[^"]{1,2000})"""",
     """"severity":\s{0,100}"({alert_severity}[^"]{1,2000})"""",
     """"category":\s{0,100}"({alert_type}[^"]{1,2000})"""",
     """"description":\s{0,100}"({additional_info}[^"]{1,2000})"""",
     """"eventDateTime":\s{0,100}"({time}[^"]{1,2000})"""",
     """"accountName":\s{0,100}"(({user_fullname}[^"\s]{1,2000}\s[^"]{1,2000})|({user}[^"]{1,2000}))"""",
     """"logonIp":\s{0,100}"({src_ip}[a-fA-F:\d.]{1,2000})"""",
     """"userPrincipalName":\s{0,100}"(-|({user_email}[^@"]{1,2000}@[^".]{1,2000}\.[^"]{1,2000})|(({user}[^\s"@]{1,2000})(@[^"]{1,2000})?))"""",

     """"domainName"{1,20}:\s{0,100}"{1,20}({domain}[^"]{1,2000})"""",
     """"logonLocation"{1,20}:\s{0,100}"{1,20}({location}[^"]{1,2000})""""
     """"userPrincipalName":\s{0,100}"({user_upn}[^"]{1,2000}?)"""",
  ]


}
```