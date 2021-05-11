#### Parser Content
```Java
{
Name = json-azure-ad-security-alert
  Vendor = Microsoft
  Product = Microsoft Azure AD Identity Protection
  Lms = Splunk
  DataType = "security-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Conditions = [ """"category": "UnfamiliarLocation"""", """"title": """, """"vendor": "Microsoft"""", """"provider": "IPC""""  ]
  Fields = [
     """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
     """"id":\s{0,100}"({alert_id}[^"]+)"""",
     """"title":\s{0,100}"({alert_name}[^"]+)"""",
     """"severity":\s{0,100}"({alert_severity}[^"]+)"""",
     """"category":\s{0,100}"({alert_type}[^"]+)"""",
     """"description":\s{0,100}"({additional_info}[^"]+)"""",
     """"eventDateTime":\s{0,100}"({time}[^"]+)"""",
     """"accountName":\s{0,100}"(({user_fullname}[^"\s]+\s[^"]+)|({user}[^"]+))"""",
     """"logonIp":\s{0,100}"({src_ip}[a-fA-F:\d.]+)"""",
     """"userPrincipalName":\s{0,100}"(-|({user_email}[^@"]+@[^".]+\.[^"]+)|(({user}[^\s"@]+)(@[^"]+)?))"""",

     """"domainName"{1,20}:\s{0,100}"{1,20}({domain}[^"]+)"""",
     """"logonLocation"{1,20}:\s{0,100}"{1,20}({location}[^"]+)""""
     """"userPrincipalName":\s{0,100}"({user_upn}[^"]+?)"""",
  ]
}
```