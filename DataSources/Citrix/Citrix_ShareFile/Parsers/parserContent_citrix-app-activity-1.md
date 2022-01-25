#### Parser Content
```Java
{
Name = citrix-app-activity-1
  DataType = "app-activity"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = ["""destinationServiceName=Citrix ShareFile""", """"ActivityType":""", """flexString1Label=application-action"""]
  Fields = ${CitrixParserTemplates.citrix-app-activity.Fields}[
    """({activity}resource-acl-updated)""",
    """"ActivityType"{1,20}:"{1,20}({activity}[^"]{1,2000})"""",
    """"TimeStamp"{1,20}:"({time}[^"]{1,2000})""",
  ]
}
citrix-app-activity = {
    Vendor = Citrix
    Product =  Citrix ShareFile
    Lms = Direct
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
      """cat=({category}.+?)\s{0,100}\w+=""",
      """\sfname=({file_path}({file_parent}[^=]{0,2000}?[\/]{1,2000})?({file_name}[^\/=]{1,2000}?(\.({file_ext}\w+))?))\s{1,100}\w+=""",
      """outcome=({file_type}.+?)\s{0,100}\w+=""",
      """\sfileType=({file_type}.+?)\s\w+=""",
      """"Email":"({user_email}[^@"]{1,2000}@({email_domain}[^@"]{1,2000}))"""",
      """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """"{1,20}EventID"{1,20}:"{1,20}({event_code}[^"]{1,2000})"{1,20}""",
      """act=({action}.+?)\s{0,100}\w+=""",
      """destinationServiceName=({app}.+?)\s{0,100}\w+=""",
      """msg=({additional_info}.+?)\s{0,100}\w+=""",
      """filePermission=({file_permissions}.+?)\s{0,100}\w+=""",
      """"Location"{1,20}:"{1,20}(-|({country_code}[^,]{1,2000})),""",
      """"(U|u)ser":"(\s|\sAnonymous|({user_fullname}[^"]{1,2000}?))\s{0,100}"""",
      """flexString1=({activity}.+?)\s{0,100}\w+=""",
      """"ActivityType"{1,20}:"{1,20}({activity}[^"]{1,2000})"""",
      """"Path"{1,20}:"({uri_path}[^"]{1,2000})""",
      """"AdditionalInfo"{1,20}:"({additional_info}[^"]{1,2000})""",
      """"Action":"({action}[^"]{1,2000})""",
      """"Company":"(\\|({company}[^"]{1,2000}?))\s{0,100}"""",
    ]

```