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
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
      """"timestamp":\s{0,100}"({time}\d{1,100})""",
      """"UserPrincipal":\s{0,100}"(?:[^"@]{1,2000}@)?({domain}[^"]{1,2000})""",
      """"aid":\s{0,100}"({aid}[^"]{1,2000})""",
      """"event_simpleName":\s{0,100}"({event_code}[^"]{1,2000})""",
      """"LogonType":\s{0,100}"({logon_type}\d{1,100})""",
      """"UserName":\s{0,100}"({user}[^"]{1,2000})""",
      """"{1,20}AuthenticationPackage"{1,20}:\s{0,100}"{1,20}({auth_package}[^"]{1,2000})"{1,20}
```