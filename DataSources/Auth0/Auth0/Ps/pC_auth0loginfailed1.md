#### Parser Content
```Java
{
Name = auth0-login-failed-1
  DataType = "failed-logon"
  Conditions = [ """"type":"f"""", """"user_id"""", """"client_name"""", """"client_id"""" ]
  Fields=${Auth0AAParserTemplates.auth0-authentication-template.Fields}[
    """"({activity_type}f)"""",
    """message"{1,20}:"{1,20}({failure_reason}[^"]{1,2000})"{1,20
auth0-authentication-template = {
    Vendor = Auth0
    Product = Auth0
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """date"{1,20}:"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)""",
      """exabeam_host=({host}[\w\-.]{1,2000})""",
      """hostname"{1,20}:"{1,20}({host}[^"]{1,2000})""",
      """description"{1,20}:"{1,20}({additional_info}[^"]{1,2000})\s{0,100}"{1,20}""",
      """"{1,20}ip"{1,20}:"{1,20}({src_ip}[\da-fA-F.:]{1,2000})""",
      """user_name"{1,20}:"{1,20}(({user_email}[^"@]{1,2000}@[^"@]{1,2000})|({user}[^"]{1,2000}))"{1,20},""",     
      """user_id"{1,20}:"{1,20}((({auth_type}[^|"]{1,2000})\|({domain}[^|"]{1,2000})\|({user}[\w-]{1,2000}))|(({=auth_type}[^|"]{1,2000})\|({=user}[\w-]{1,2000})))"""
      """client_name"{1,20}:"{1,20}({app}[^"]{1,2000})""",
      """user_agent"{1,20}:"{1,20}({user_agent}[^"]{1,2000})""",         
      """severity"{1,20}:"{1,20}({alert_severity}[^"]{1,2000})""", 
    
}
```