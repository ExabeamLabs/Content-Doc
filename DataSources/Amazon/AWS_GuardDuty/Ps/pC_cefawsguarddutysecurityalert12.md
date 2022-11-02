#### Parser Content
```Java
{
Name = cef-aws-guardduty-security-alert-12
  Conditions = [ """CEF:""", """destinationServiceName =AWS""", """,ServiceName: guardduty,""", """,Type: Execution:EC2/SuspiciousFile,""" ]

cef-aws-guardduty-security-alert-template-1 = {
    Vendor = Amazon
    Product = AWS GuardDuty
    Lms = Splunk
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """,CreatedAt:\s{0,100}({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ),""",
      """,LocalIpDetails:[^\}]{1,2000}IpAddressV4:\s{0,100}({src_ip}[A-Fa-f\d:.]{1,2000})""",
      """,RemoteIpDetails:[^\]]{1,2000}IpAddressV4:\s{0,100}({dest_ip}[A-Fa-f\d:.]{1,2000})""",
      """,Title:\s{0,100}({event_name}[^:]{1,2000}?)\.?,\w{1,2000}:""",
      """,Type:\s{0,1000}({alert_type}[^:]{1,2000}):({alert_name}[^:]{1,2000}?),\w{1,2000}:""",
      """,Severity:\s{0,100}({alert_severity}[^,]{1,2000}),""",
      """,Region:\s{0,100}({region}[^:]{1,2000}),\w{1,2000}:""",
      """,Description:\s{0,100}({additional_info}[^:]{1,2000}?)\.?,\w{1,2000}:""",
      """AccountId:\s{0,100}({account_id}[^,]{1,2000}),""",
      """ResourceType:\s{0,100}({resource_type}[^,\}]{1,2000})""",
      """,Arn:\s{0,100}({object}[^,]{1,2000}),\w{1,2000}:""",
      """,UserName:\s{0,100}({user}[^,\}]{1,2000})""",
      """,UserType:\s{0,100}({user_type}[^,\}]{1,2000})"""
    
}
```