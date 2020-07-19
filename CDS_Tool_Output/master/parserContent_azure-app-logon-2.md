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
    """exabeam_host=([^=@]+@\s*)?({host}\S+)""",
    """"TimeGenerated":"({time}\d+-\d+-\d+T\d+:\d+:\d+)"""
    """"IPAddress":"({src_ip}[A-Fa-f:\d.]+)"""",
    """"UserPrincipalName":"({user_email}[^"\s@]+@[^"\s@]+)"""",
    """"browser":"({browser}[^"]+)"""",
    """"ConditionalAccessStatus":"({outcome}[^"]+)"""",
    """\sdestinationServiceName=({app}[^=]+?)\s+\w+="""
    """\sext_AppDisplayName=({app}[^=]+?)\s+\w+="""
    """\sext_DeviceDetail=\{[^\}]+?"displayName":"({src_host}[^"]+)"""
    """\sext_DeviceDetail=\{[^\}]+?"operatingSystem":"({os}[^"]+)"""
    """UserDisplayName"+:"+({user_fullname}[^"]+)""",
    """UserId"+:"+({user_id}[^"]+)""",
    """"+IPAddress"+:"+({src_ip}[^"]+)""",
    """"browser\\*"+:\\*"+({browser}[^"]+)\\"+""",
    """"UserAgent\\*"+:\\*"+({user_agent}[^"]+)""",
    """src-application-name"+:"+({app}[^"]+)""",
    """"operatingSystem\\*"+:\\*"+({os}[^"]+)\\"+"""
  ]
}
```