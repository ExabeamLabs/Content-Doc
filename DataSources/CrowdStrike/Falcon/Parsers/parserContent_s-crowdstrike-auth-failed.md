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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"timestamp":"({time}\d{1,100})""",
    """"UserName":\s{0,100}"({user_email}[^"@]+@[^"@]+)"""",
    """"UserName":\s{0,100}"({user}[^"@]+)"""",
    """"UserSid":\s{0,100}"({user_sid}[^"]+)"""",
    """"event_simpleName":"({event_code}[^"]+)""",
    """"aid":"({aid}[^"]+)""",
    """"aip":\s{0,100}"({aip}[^"]+)"""
  ]
}
```