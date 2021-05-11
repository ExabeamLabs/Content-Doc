#### Parser Content
```Java
{
Name = citrix-app-activity-1
  DataType = "app-activity"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = ["""destinationServiceName=Citrix ShareFile""", """"ActivityType":""", """flexString1Label=application-action"""]
  Fields = ${CitrixParserTemplates.citrix-app-activity.Fields}[
    """({activity}resource-acl-updated)""",
    """"ActivityType"{1,20}:"{1,20}({activity}[^"]+)"""",
    """"TimeStamp"{1,20}:"({time}[^"]+)""",
  ]
}
citrix-app-activity = {
    Vendor = Citrix
    Product =  Citrix ShareFile
    Lms = Direct
    Fields = [
      """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
      """cat=({category}.+?)\s{0,100}\w+=""",
      """\sfname=({file_path}({file_parent}[^=]*?[\/]+)?({file_name}[^\/=]+?(\.({file_ext}\w+))?))\s{1,100}\w+=""",
      """outcome=({file_type}.+?)\s{0,100}\w+=""",
      """\sfileType=({file_type}.+?)\s\w+=""",
      """"Email":"({user_email}[^@"]+@({email_domain}[^@"]+))"""",
      """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """"{1,20}EventID"{1,20}:"{1,20}({event_code}[^"]+)"{1,20}""",
      """act=({action}.+?)\s{0,100}\w+=""",
      """destinationServiceName=({app}.+?)\s{0,100}\w+=""",
      """msg=({additional_info}.+?)\s{0,100}\w+=""",
      """filePermission=({file_permissions}.+?)\s{0,100}\w+=""",
      """"Location"{1,20}:"{1,20}(-|({country_code}[^,]+)),""",
      """"(U|u)ser":"(\s|\sAnonymous|({user_fullname}[^"]+?))\s{0,100}"""",
      """flexString1=({activity}.+?)\s{0,100}\w+=""",
      """"ActivityType"{1,20}:"{1,20}({activity}[^"]+)"""",
      """"Path"{1,20}:"({uri_path}[^"]+)""",
      """"AdditionalInfo"{1,20}:"({additional_info}[^"]+)""",
      """"Action":"({action}[^"]+)""",
      """"Company":"(\\|({company}[^"]+?))\s{0,100}"""",
    ]

```