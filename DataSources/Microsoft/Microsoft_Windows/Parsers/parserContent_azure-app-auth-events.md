#### Parser Content
```Java
{
Name = azure-app-auth-events
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"OperationName":"Sign-in activity"""", """"ConditionalAccessStatus":"""", """"enforcedGrantControls":["RequireDuoMfa"]""" ]
  Fields = [
    """exabeam_host=([^=@]{1,2000}@\s{0,100})?({host}\S+)""",
    """"TimeGenerated":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})"""
    """"IPAddress":"({src_ip}[A-Fa-f:\d.]{1,2000})"""",
    """"UserPrincipalName":"({user_email}[^"\s@]{1,2000}@({email_domain}[^"\s@]{1,2000}))"""",
    """"browser":"({browser}[^"]{1,2000})"""",
    """"ConditionalAccessStatus":"({outcome}[^"]{1,2000})"""",
    """\sext_DeviceDetail=\{[^\}]{1,2000}?"displayName":"({src_host}[^"]{1,2000})"""
    """\sext_DeviceDetail=\{[^\}]{1,2000}?"operatingSystem":"({os}[^"]{1,2000})"""
    """UserDisplayName"{1,20}:"{1,20}({user_fullname}[^"]{1,2000})""",
    """UserId"{1,20}:"{1,20}({user_id}[^"]{1,2000})""",
    """"{1,20}IPAddress"{1,20}:"{1,20}({src_ip}[^"]{1,2000})""",
    """"browser\\*"{1,20}:\\*"{1,20}({browser}[^"]{1,2000})\\"{1,20}""",
    """"UserAgent\\*"{1,20}:\\*"{1,20}({user_agent}[^"]{1,2000})""",
    """"operatingSystem\\*"{1,20}:\\*"{1,20}({os}[^"]{1,2000})\\"{1,20}""",
    """"ResourceDisplayName":"({app}[^"]{1,2000})""",
    """"SourceSystem"{1,20}:"{1,20}({dest_host}[^"]{1,2000})""",
    """"ClientAppUsed"{1,20}:"{1,20}({category}[^"]{1,2000})""",
    """"AppDisplayName"{1,20}:"{1,20}({resource}[^"]{1,2000})""",
    """"countryOrRegion\\*"{1,20}:\\*"{1,20}({country}[^"]{1,2000})\\"{1,20}""",
    """"city\\*"{1,20}:\\*"{1,20}({city}[^"]{1,2000})\\"{1,20}""",
    """"\$table"{1,20}:"{1,20}({database_name}[^"]{1,2000})""",
  ]
}
```