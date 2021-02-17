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
    """exabeam_host=([^=@]+@\s*)?({host}\S+)""",
    """"TimeGenerated":"({time}\d+-\d+-\d+T\d+:\d+:\d+)"""
    """"IPAddress":"({src_ip}[A-Fa-f:\d.]+)"""",
    """"UserPrincipalName":"({user_email}[^"\s@]+@({email_domain}[^"\s@]+))"""",
    """"browser":"({browser}[^"]+)"""",
    """"ConditionalAccessStatus":"({outcome}[^"]+)"""",
    """\sext_DeviceDetail=\{[^\}]+?"displayName":"({src_host}[^"]+)"""
    """\sext_DeviceDetail=\{[^\}]+?"operatingSystem":"({os}[^"]+)"""
    """UserDisplayName"+:"+({user_fullname}[^"]+)""",
    """UserId"+:"+({user_id}[^"]+)""",
    """"+IPAddress"+:"+({src_ip}[^"]+)""",
    """"browser\\*"+:\\*"+({browser}[^"]+)\\"+""",
    """"UserAgent\\*"+:\\*"+({user_agent}[^"]+)""",
    """"operatingSystem\\*"+:\\*"+({os}[^"]+)\\"+""",
    """"ResourceDisplayName":"({app}[^"]+)""",
    """"SourceSystem"+:"+({dest_host}[^"]+)""",
    """"ClientAppUsed"+:"+({category}[^"]+)""",
    """"AppDisplayName"+:"+({resource}[^"]+)""",
    """"countryOrRegion\\*"+:\\*"+({country}[^"]+)\\"+""",
    """"city\\*"+:\\*"+({city}[^"]+)\\"+""",
    """"\$table"+:"+({database_name}[^"]+)""",
  ]
}
```