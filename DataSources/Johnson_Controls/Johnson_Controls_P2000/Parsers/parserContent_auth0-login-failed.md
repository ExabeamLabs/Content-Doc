#### Parser Content
```Java
{
Name = auth0-login-failed
  DataType = "failed-logon"
  Conditions = [ """"type":"fp"""", """"user_id"""", """"client_name"""", """"client_id"""" ]
  Fields=${Auth0AAParserTemplates.auth0-authentication-template.Fields}[
    """"({activity_type}fp)"""",
    """consoleOut"{1,20}:"{1,20}({failure_reason}[^"]+)"{1,20}""",
  ]
}
auth0-authentication-template = {
    Vendor = Auth0
    Product = Auth0
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """date"{1,20}:"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)""",
      """exabeam_host=({host}[\w\-.]+)""",
      """hostname"{1,20}:"{1,20}({host}[^"]+)""",
      """description"{1,20}:"{1,20}({additional_info}[^"]+)\s{0,100}"{1,20}""",
      """"{1,20}ip"{1,20}:"{1,20}({src_ip}[\da-fA-F.:]+)""",
      """user_name"{1,20}:"{1,20}(({user_email}[^"@]+@[^"@]+)|({user}[^"]+))"{1,20},""",     
      """user_id"{1,20}:"{1,20}((({auth_type}[^|"]+)\|({domain}[^|"]+)\|({user}[\w-]+))|(({=auth_type}[^|"]+)\|({=user}[\w-]+)))"""
      """client_name"{1,20}:"{1,20}({app}[^"]+)""",
      """user_agent"{1,20}:"{1,20}({user_agent}([^\/]+\/\s{1,100}(?i)({os}iOS|Android|BlackBerry|Windows Phone|BeOS|x11|windows|linux|macintosh|darwin))?[^"]+)""",         
      """severity"{1,20}:"{1,20}({alert_severity}[^"]+)""", 
    ]

```