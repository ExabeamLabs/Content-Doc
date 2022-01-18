#### Parser Content
```Java
{
Name = s-crowdstrike-app-login-7
  Conditions = [ """"eventType":""", """"AuthActivityAuditEvent"""", """"OperationName":""", """"streamStarted"""" ]

s-crowdstrike-app-login = {
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "epoch"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"eventCreationTime":\s{0,100}({time}\d{1,100})""",
    """"UserId":\s{0,100}"({user_email}[^"@]{1,2000}@({email_domain}[^"@]{1,2000}))"""",
    """"UserId":\s{0,100}"({user}[^"@]{1,2000})"""",
    """"UserIp":\s{0,100}"({src_ip}[^"]{1,2000})""",
    """"ServiceName":\s{0,100}"({app}[^"]{1,2000})""",
    """"Success":\s{0,100}({outcome}[^",]{1,2000})""",
  
}
```