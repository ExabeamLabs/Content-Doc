#### Parser Content
```Java
{
Name = s-crowdstrike-auth-failed
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Splunk
  DataType = "authentication-failed"
  TimeFormat = "epoch"
  Conditions = [ """"event_simpleName":"UserLogonFailed""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"timestamp":"({time}\d{1,100})""",
    """"UserName":\s{0,100}"({user_email}[^"@]{1,2000}@[^"@]{1,2000})"""",
    """"UserName":\s{0,100}"({user}[^"@]{1,2000})"""",
    """"UserSid":\s{0,100}"({user_sid}[^"]{1,2000})"""",
    """"event_simpleName":"({event_code}[^"]{1,2000})""",
    """"aid":"({aid}[^"]{1,2000})""",
    """"aip":\s{0,100}"({aip}[^"]{1,2000})"""
  ]
}
```