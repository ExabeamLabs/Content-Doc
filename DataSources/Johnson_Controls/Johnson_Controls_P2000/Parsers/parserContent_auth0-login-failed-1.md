#### Parser Content
```Java
{
Name = auth0-login-failed-1
  DataType = "failed-logon"
  Conditions = [ """"type":"f"""", """"user_id"""", """"client_name"""", """"client_id"""" ]
  Fields=${Auth0AAParserTemplates.auth0-authentication-template.Fields}[
    """"({activity_type}f)"""",
    """message"+:"+({failure_reason}[^"]+)"+,""",
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