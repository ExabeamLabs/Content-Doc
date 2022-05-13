#### Parser Content
```Java
{
Name = azure-atp-security-alert-5
  Product = Azure Advanced Threat Protection
  Conditions = [ """"category":"RemoteExecutionSecurityAlert"""", """vendor":"Microsoft"""", """"sourcetype":"GraphSecurityAlert"""", """provider":"Azure Advanced Threat Protection"""" ]

defender-atp-security-alert-events = {
    Vendor = Microsoft
    Lms = Syslog
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,3}Z)"""",
      """"hostname":"({host}[^"]{1,2000})"""",
      """"severity":"({alert_severity}[^"]{1,2000})"""",
      """privateIpAddress":"({src_ip}[a-fA-F\d:.]{1,2000})"""",
      """publicIpAddress":"({dest_ip}[a-fA-F\d:.]{1,2000})"""",
      """"title":"({alert_name}[^"]{1,2000})"""",
      """"category":"({alert_type}[^"]{1,2000})"""",
      """"description":"({additional_info}[^\n]{1,2000}?)\s{0,100}","""",
      """userPrincipalName":"({user_email}[^@"]{1,2000}@[^@"]{1,2000})"""",
      """accountName":"({user}[^"]{1,2000})""",
      """domainName":"({domain}[^"]{1,2000})"""
    
}
```