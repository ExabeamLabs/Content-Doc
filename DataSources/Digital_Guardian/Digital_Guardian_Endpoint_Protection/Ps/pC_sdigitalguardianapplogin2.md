#### Parser Content
```Java
{
Name = s-digitalguardian-app-login-2
  Conditions = [ """Operation="Application Start"""" , """Agent_UTC_Time=""" ]

splunk-digitalguardian-app-login = {
  Vendor = Digital Guardian
  Product = Digital Guardian Endpoint Protection
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Fields = [
    """(\s|exabeam_\w+=)(Agent_UTC_Time|Server_UTC_Timestamp)="({time}\d{1,100}\/\d{1,100}\/\d\d\d\d \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))"""",
    """exabeam_host=([^@=]{1,2000}?@\s{0,100})?({host}[^\s]{1,2000})""",
    """(\s|exabeam_\w+=)Computer_Name ="([^\/"]{1,2000}\/)?({host}[^"]{1,2000})"""",
    """(\s|exabeam_\w+=)User_Name ="(?:|(({domain}[^"\/\\]{1,2000})[\/\\]{1,2000})?({user}[^"]{1,2000}))"""",
    """(\s|exabeam_\w+=)Domain_Name ="(?:|({domain}[^"]{1,2000}))"""",
    """(\s|exabeam_\w+=)Application="(?:|({app}[^"]{1,2000}))"""",
    """(\s|exabeam_\w+=)Operation="(?:|({event_code}[^"]{1,2000}))"""",
  
}
```