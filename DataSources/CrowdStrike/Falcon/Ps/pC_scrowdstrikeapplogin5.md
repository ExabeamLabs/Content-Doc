#### Parser Content
```Java
{
Name = s-crowdstrike-app-login-5
  Conditions = [ """"eventType":""", """"RemoteResponseSessionStartEvent"""", """UserName""" ]
  Fields = ${CrowdStrikeParserTemplates.s-crowdstrike-app-login.Fields} [
    """"UserName":\s{0,100}"({user_email}[^"@]{1,2000}@[^"@]{1,2000})"""",
    """"UserName":\s{0,100}"({user}[^"@]{1,2000})"""",
    """"HostnameField":\s{0,100}"({host}[^"@]{1,2000})"""",
    """destinationServiceName =({app}[^=]{1,2000})\s\w+=""",
    """({event_name}RemoteResponseSessionStartEvent)""",
    """"SessionId":"({session_id}[^",]{1,2000})"""",
    """"(?i)EventType":\s{0,100}"({activity_details}[^",]{1,2000})""""
  ]
  DupFields = ["event_name->activity"]

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
    """"UTCTimestamp":({time}\d{1,16})""",
    """"UserId":\s{0,100}"({user_email}[^"@]{1,2000}@({email_domain}[^"@]{1,2000}))"""",
    """"UserId":\s{0,100}"({user}[^"@]{1,2000})"""",
    """"UserIp":\s{0,100}"({src_ip}[^"]{1,2000})""",
    """"ServiceName":\s{0,100}"({app}[^"]{1,2000})""",
    """"Success":\s{0,100}({outcome}[^",]{1,2000})"""
  
}
```