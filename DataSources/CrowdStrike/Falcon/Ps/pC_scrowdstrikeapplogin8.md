#### Parser Content
```Java
{
Name = s-crowdstrike-app-login-8
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"  
  Conditions = [ """"event-name":""", """"audit-event"""", """"OperationName":"twoFactorAuthenticate"""" ]
  Fields =  ${CrowdStrikeParserTemplates.s-crowdstrike-app-login.Fields} [
    """"time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    """"OperationName":"({event_name}[^"]{1,2000})"""
 ]

s-crowdstrike-app-login = {
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "epoch"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"eventCreationTime":\s{0,100}({time}\d{1,100})""",
    """"timestamp":"({time}[^",]{1,2000})"""",
    """"UserId":\s{0,100}"({user_email}[^"@]{1,2000}@({email_domain}[^"@]{1,2000}))"""",
    """"UserId":\s{0,100}"({user}[^"@]{1,2000})"""",
    """"UserIp":\s{0,100}"({src_ip}[^"]{1,2000})""",
    """"ServiceName":\s{0,100}"({app}[^"]{1,2000})""",
    """"Success":\s{0,100}({outcome}[^",]{1,2000})"""
  
}
```