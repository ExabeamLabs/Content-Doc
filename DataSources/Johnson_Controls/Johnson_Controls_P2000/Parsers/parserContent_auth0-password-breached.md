#### Parser Content
```Java
{
Name = auth0-password-breached
  DataType = "security-alert"
  Conditions = [ """"type":"pwd_leak"""", """"user_id"""", """"client_id"""" ]
  Fields=${Auth0AAParserTemplates.auth0-authentication-template.Fields}[
    """"({alert_name}pwd_leak)"""",
  ]
}
auth0-authentication-template = {
    Vendor = Auth0
    Product = Auth0
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """date"+:"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)""",
      """exabeam_host=({host}[\w\-.]+)""",
      """hostname"+:"+({host}[^"]+)""",
      """description"+:"+({additional_info}[^"]+)\s*"+""",
      """"+ip"+:"+({src_ip}[\da-fA-F.:]+)""",
      """user_name"+:"+(({user_email}[^"@]+@[^"@]+)|({user}[^"]+))"+,""",     
      """user_id"+:"+((({auth_type}[^|"]+)\|({domain}[^|"]+)\|({user}[\w-]+))|(({=auth_type}[^|"]+)\|({=user}[\w-]+)))"""
      """client_name"+:"+({app}[^"]+)""",
      """user_agent"+:"+({user_agent}([^\/]+\/\s+(?i)({os}iOS|Android|BlackBerry|Windows Phone|BeOS|x11|windows|linux|macintosh|darwin))?[^"]+)""",         
      """severity"+:"+({alert_severity}[^"]+)""", 
    ]

```