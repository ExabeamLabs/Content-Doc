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
      """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
      """"timestamp":\s{0,100}"({time}\d{1,100})""",
      """"UserPrincipal":\s{0,100}"(?:[^"@]+@)?({domain}[^"]+)""",
      """"aid":\s{0,100}"({aid}[^"]+)""",
      """"event_simpleName":\s{0,100}"({event_code}[^"]+)""",
      """"LogonType":\s{0,100}"({logon_type}\d{1,100})""",
      """"UserName":\s{0,100}"({user}[^"]+)""",
      """"{1,20}AuthenticationPackage"{1,20}:\s{0,100}"{1,20}({auth_package}[^"]+)"{1,20}
```