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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"timestamp":"({time}\d+)""",
    """"UserName":\s*"({user_email}[^"@]+@[^"@]+)"""",
    """"UserName":\s*"({user}[^"@]+)"""",
    """"UserSid":\s*"({user_sid}[^"]+)"""",
    """"event_simpleName":"({event_code}[^"]+)""",
    """"aid":"({aid}[^"]+)""",
    """"aip":\s*"({aip}[^"]+)"""
  ]
}
```