#### Parser Content
```Java
{
Name = crowdstrike-user-identity
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Direct
    DataType = "logon"
    TimeFormat = "epoch"
    Conditions = [ """"event_simpleName":""", """"UserIdentity"""", """"aid"""" ]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
      """"timestamp":\s*"({time}\d+)""",
      """"UserPrincipal":\s*"(?:[^"@]+@)?({domain}[^"]+)""",
      """"aid":\s*"({aid}[^"]+)""",
      """"event_simpleName":\s*"({event_code}[^"]+)""",
      """"LogonType":\s*"({logon_type}\d+)""",
      """"UserName":\s*"({user}[^"]+)""",
      """"+AuthenticationPackage"+:\s*"+({auth_package}[^"]+)"+,""",
      """"+event_platform"+:\s*"+({event_platform}[^"]+)"+"""
    ]
  }
```