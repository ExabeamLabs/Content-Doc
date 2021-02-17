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
     """exabeam_host=([^=]+@\s*)?({host}\S+)""",
     """"id":\s*"({alert_id}[^"]+)"""",
     """"title":\s*"({alert_name}[^"]+)"""",
     """"severity":\s*"({alert_severity}[^"]+)"""",
     """"category":\s*"({alert_type}[^"]+)"""",
     """"description":\s*"({additional_info}[^"]+)"""",
     """"eventDateTime":\s*"({time}[^"]+)"""",
     """"accountName":\s*"(({user_fullname}[^"\s]+\s[^"]+)|({user}[^"]+))"""",
     """"logonIp":\s*"({src_ip}[a-fA-F:\d.]+)"""",
     """"userPrincipalName":\s*"(({user_email}[^@]+@[^"]+)|({user}[^"]+))""",
     """"domainName"+:\s*"+({domain}[^"]+)"""",
     """"logonLocation"+:\s*"+({location}[^"]+)""""
  ]
}
```