#### Parser Content
```Java
{
Name = s-crowdstrike-app-login-5
  Conditions = [ """"eventType":""", """"RemoteResponseSessionStartEvent"""", """UserName""" ]
  Fields = ${CrowdStrikeParserTemplates.s-crowdstrike-app-login.Fields} [
    """"UserName":\s*"({user_email}[^"@]+@[^"@]+)"""",
    """"UserName":\s*"({user}[^"@]+)"""",
    """"HostnameField":\s*"({host}[^"@]+)"""",
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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"eventCreationTime":\s*({time}\d+)""",
    """"UserId":\s*"({user_email}[^"@]+@[^"@]+)"""",
    """"UserId":\s*"({user}[^"@]+)"""",
    """"UserIp":\s*"({src_ip}[^"]+)""",
    """"ServiceName":\s*"({app}[^"]+)""",
    """"Success":\s*({outcome}[^",]+)""",
  ]

```