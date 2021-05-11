#### Parser Content
```Java
{
Name = s-crowdstrike-app-login-5
  Conditions = [ """"eventType":""", """"RemoteResponseSessionStartEvent"""", """UserName""" ]
  Fields = ${CrowdStrikeParserTemplates.s-crowdstrike-app-login.Fields} [
    """"UserName":\s{0,100}"({user_email}[^"@]+@[^"@]+)"""",
    """"UserName":\s{0,100}"({user}[^"@]+)"""",
    """"HostnameField":\s{0,100}"({host}[^"@]+)"""",
    """destinationServiceName=({app}.+?)\s(\w+=|$)"""
  ]
}
s-crowdstrike-app-login = {
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "epoch"
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"eventCreationTime":\s{0,100}({time}\d{1,100})""",
    """"UserId":\s{0,100}"({user_email}[^"@]+@({email_domain}[^"@]+))"""",
    """"UserId":\s{0,100}"({user}[^"@]+)"""",
    """"UserIp":\s{0,100}"({src_ip}[^"]+)""",
    """"ServiceName":\s{0,100}"({app}[^"]+)""",
    """"Success":\s{0,100}({outcome}[^",]+)""",
  ]

```