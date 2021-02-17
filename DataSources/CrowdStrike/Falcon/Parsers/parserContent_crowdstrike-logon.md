#### Parser Content
```Java
{
Name = crowdstrike-logon
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Direct
    DataType = "logon"
    TimeFormat = "epoch"
    Conditions = [ """"event_simpleName":"UserLogon"""", """"aid"""" ]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
      """({host}[\w\-.]+)\s+Skyformation""",
      """"AuthenticationPackage":"({auth_package}[^"]+)""",
      """"timestamp":"({time}\d+)""",
      """"LogonType":"({logon_type}\d+)""",
      """"UserName":"({user}[^"]+)""",
      """"UserName":"({dest_host}[^"$]+)\$""",
      """"UserPrincipal":"({user_email}[^"]+)""",
      """"UserSid":"({user_sid}[^"]+)""",
      """"aid":"({aid}[^"]+)""",
      """"event_simpleName":"({event_code}[^"]+)"""
    ]
  }
```