#### Parser Content
```Java
{
Name = citrix-app-activity-1
  DataType = "app-activity"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = ["""destinationServiceName =Citrix ShareFile""", """"ActivityType":""", """"ActionDetails":"""]
  Fields = ${CitrixParserTemplates.citrix-app-activity.Fields}[
    """({activity}resource-acl-updated)""",
    """"ActivityType"{1,20}:"{1,20}({activity}[^"]{1,2000})"""",
    """"TimeStamp"{1,20}:"{1,20}({time}\d{1,2}\/\d{1,2}\/\d{1,4}\s\d{1,2}:\d{1,2}:\d{1,2}\s(AM|PM))""",
    """"Path"{1,20}:"{1,20}({file_path}({file_parent}[^"]{0,2000}?[\/]{1,20})?({file_name}[^\/"]{1,2000}?(\.({file_ext}[^\/"]{1,2000}))?))"""",
    """"ChangeSourceIP"{1,20}:"{1,20}({src_ip}[A-Fa-f\d:.]{1,2000})"""",
    """"ActionDetails"{1,20}:"{1,20}({file_permissions}[^"]{1,2000})"{1,20
citrix-app-activity = {
    Vendor = Citrix
    Product =  Citrix ShareFile
    Lms = Direct
    Fields = [
      """"Date"{1,20}:"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
      """"Email":"({user_email}[^@"]{1,2000}@({email_domain}[^@"]{1,2000}))"""",
      """"IPAddress"{1,20}:"{1,20}({src_ip}[A-Fa-f\d:.]{1,2000})"""",
      """"{1,20}EventID"{1,20}:"{1,20}({event_code}[^"]{1,2000})"{1,20}""",
      """destinationServiceName =({app}[^=]{1,2000}?)\s{0,100}\w+=""",
      """"Location"{1,20}:"{1,20}(-|({country_code}[^,]{1,2000})),""",
      """"(U|u)ser":"(\s|\sAnonymous|({user_fullname}[^"]{1,2000}?))\s{0,100}"""",
      """"ActivityType"{1,20}:"{1,20}({activity}[^"]{1,2000})"""",
      """"Activity"{1,20}:"{1,20}({activity}[^"]{1,2000})"""",
      """"Path"{1,20}:"({uri_path}[^"]{1,2000})""",
      """"AdditionalInfo"{1,20}:"({additional_info}[^"]{1,2000})""",
      """"Action":"({action}[^"]{1,2000})""",
      """"Company":"(\\|({company}[^"]{1,2000}?))\s{0,100}"""",
    
}
```