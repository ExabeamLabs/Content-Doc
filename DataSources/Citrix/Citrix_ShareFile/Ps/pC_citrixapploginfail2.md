#### Parser Content
```Java
{
Name = citrix-app-login-fail-2
  DataType = "app-login-fail"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """destinationServiceName =Citrix ShareFile""", """Activity":"LoginLocked""", """"Email":""" ]

citrix-app-activity = {
    Vendor = Citrix
    Product =  Citrix ShareFile
    Lms = Direct
    Fields = [
      """"Date"{1,20}:"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
      """"UserMakingChangeEmailAddress":"({user_email}[^@"]{1,2000}@({email_domain}[^@\."]{1,2000}\.[^"]{1,2000}))"""",
      """"Email":"({user_email}[^@"]{1,2000}@({email_domain}[^@"]{1,2000}))"""",
      """"IPAddress"{1,20}:"{1,20}({src_ip}[A-Fa-f\d:.]{1,2000})"""",
      """"{1,20}EventID"{1,20}:"{1,20}({event_code}[^"]{1,2000})"{1,20}""",
      """destinationServiceName =({app}[^=]{1,2000}?)\s{0,100}\w+=""",
      """"Location"{1,20}:"{1,20}(-\s{0,20}|({country_code}[^,]{1,2000})),""",
      """"(U|u)ser":"\s{0,20}(\s|\sAnonymous|({user_fullname}[^"]{1,2000}?))\s{0,100}"""",
      """"ActivityType"{1,20}:"{1,20}({activity}[^"]{1,2000})"""",
      """"Activity"{1,20}:"{1,20}({activity}[^"]{1,2000})"""",
      """"Path"{1,20}:"({uri_path}[^"]{1,2000})""",
      """"AdditionalInfo"{1,20}:"({additional_info}[^"]{1,2000})""",
      """"Action":"({action}[^"]{1,2000})""",
      """"Company":"\s{0,20}(\\|({company}[^"]{1,2000}?))\s{0,100}"""",
    
}
```