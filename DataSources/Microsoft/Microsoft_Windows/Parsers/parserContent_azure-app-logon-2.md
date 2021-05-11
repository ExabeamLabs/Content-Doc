#### Parser Content
```Java
{
Name = azure-app-logon-2
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"OperationName":"Sign-in activity"""", """"ConditionalAccessStatus":"""" ]
  Fields = [
    """exabeam_host=([^=@]+@\s{0,100})?({host}\S+)""",
    """"TimeGenerated":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})"""
    """"IPAddress":"({src_ip}[A-Fa-f:\d.]+)"""",
    """"UserPrincipalName":"({user_email}[^"\s@]+@({email_domain}[^"\s@]+))"""",
    """"browser":"({browser}[^"]+)"""",
    """"ConditionalAccessStatus":"({outcome}[^"]+)"""",
    """\sdestinationServiceName=({app}[^=]+?)\s{1,100}\w+="""
    """\sext_AppDisplayName=({app}[^=]+?)\s{1,100}\w+="""
    """\sext_DeviceDetail=\{[^\}]+?"displayName":"({src_host}[^"]+)"""
    """\sext_DeviceDetail=\{[^\}]+?"operatingSystem":"({os}[^"]+)"""
    """UserDisplayName"{1,20}:"{1,20}({user_fullname}[^"]+)""",
    """UserId"{1,20}:"{1,20}({user_id}[^"]+)""",
    """"{1,20}IPAddress"{1,20}:"{1,20}({src_ip}[^"]+)""",
    """"browser":"({browser}[^"]+)""", 
    """"UserAgent\\*"{1,20}:\\*"{1,20}({user_agent}[^"]+)""",
    """src-application-name"{1,20}:"{1,20}({app}[^"]+)""",
    """"operatingSystem":"({os}[^"]+)""", 
    """"failureReason":"({failure_reason}.+?)(\.)?"""",
  ]
}
```