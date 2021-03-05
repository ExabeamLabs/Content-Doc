#### Parser Content
```Java
{
Name = crowdstrike-user-identity
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Direct
    DataType = "logon"
    TimeFormat = "epoch"
    Conditions = [ """"event_simpleName":"UserIdentity"""", """"aid"""" ]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
      """({host}[\w\-.]+)\s+Skyformation""",
      """"timestamp":"({time}\d+)""",
      """"UserPrincipal":"(?:[^"@]+@)?({dest_host}[^"]+)""",
      """"aid":"({aid}[^"]+)""",
      """"event_simpleName":"({event_code}[^"]+)""",
      """"LogonType":"({logon_type}\d+)""",
      """"UserName":"({user}[^"]+)""",
      """"+AuthenticationPackage"+:"+({auth_package}[^"]+)"+,""",
      """"+event_platform"+:"+({event_platform}[^"]+)"+"""
    ]
  }
```