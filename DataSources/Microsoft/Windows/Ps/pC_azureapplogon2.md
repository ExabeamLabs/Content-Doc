#### Parser Content
```Java
{
Name = azure-app-logon-2
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"OperationName":"Sign-in activity"""", """"ConditionalAccessStatus":"""" ]
  Fields = [
    """exabeam_host=([^=@]{1,2000}@\s{0,100})?({host}\S+)""",
    """"TimeGenerated":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})"""
    """"IPAddress":"({src_ip}[A-Fa-f:\d.]{1,2000})"""",
    """"UserPrincipalName":"({user_email}[^"\s@]{1,2000}@({email_domain}[^"\s@]{1,2000}))"""",
    """"browser":"({browser}[^"]{1,2000})"""",
    """"ConditionalAccessStatus":"({outcome}[^"]{1,2000})"""",
    """\sdestinationServiceName =({app}[^=]{1,2000}?)\s{1,100}\w+="""
    """\sext_AppDisplayName =({app}[^=]{1,2000}?)\s{1,100}\w+="""
    """\sext_DeviceDetail=\{[^\}]{1,2000}?"displayName":"({src_host}[^"]{1,2000})"""
    """\sext_DeviceDetail=\{[^\}]{1,2000}?"operatingSystem":"({os}[^"]{1,2000})"""
    """UserDisplayName"{1,20}:"{1,20}({user_fullname}[^"]{1,2000})""",
    """UserId"{1,20}:"{1,20}({user_id}[^"]{1,2000})""",
    """"{1,20}IPAddress"{1,20}:"{1,20}({src_ip}[^"]{1,2000})""",
    """"browser":"({browser}[^"]{1,2000})""", 
    """"UserAgent\\*"{1,20}:\\*"{1,20}({user_agent}[^"]{1,2000})""",
    """src-application-name"{1,20}:"{1,20}({app}[^"]{1,2000})""",
    """"operatingSystem":"({os}[^"]{1,2000})""", 
    """"failureReason":"({failure_reason}.+?)(\.)?"""",
  ]


}
```