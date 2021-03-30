#### Parser Content
```Java
{
Name = citrix-app-activity-1
  DataType = "app-activity"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = ["""destinationServiceName=Citrix ShareFile""", """"ActivityType":""", """flexString1Label=application-action"""]
  Fields = ${CitrixParserTemplates.citrix-app-activity.Fields}[
    """({activity}resource-acl-updated)""",
    """"ActivityType"+:"+({activity}[^"]+)"""",
    """"TimeStamp"+:"({time}[^"]+)""",
  ]
}
citrix-app-activity = {
    Vendor = Citrix
    Product =  Citrix ShareFile
    Lms = Direct
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}\S+)""",
      """cat=({category}.+?)\s*\w+=""",
      """\sfname=({file_path}({file_parent}[^=]*?[\/]+)?({file_name}[^\/=]+?(\.({file_ext}\w+))?))\s+\w+=""",
      """outcome=({file_type}.+?)\s*\w+=""",
      """\sfileType=({file_type}.+?)\s\w+=""",
      """"Email":"({user_email}[^@"]+@({email_domain}[^@"]+))"""",
      """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """"+EventID"+:"+({event_code}[^"]+)"+""",
      """act=({action}.+?)\s*\w+=""",
      """destinationServiceName=({app}.+?)\s*\w+=""",
      """msg=({additional_info}.+?)\s*\w+=""",
      """filePermission=({file_permissions}.+?)\s*\w+=""",
      """"Location"+:"+(-|({country_code}[^,]+)),""",
      """"(U|u)ser":"(\s|\sAnonymous|({user_fullname}[^"]+?))\s*"""",
      """flexString1=({activity}.+?)\s*\w+=""",
      """"ActivityType"+:"+({activity}[^"]+)"""",
      """"Path"+:"({uri_path}[^"]+)""",
      """"AdditionalInfo"+:"({additional_info}[^"]+)""",
      """"Action":"({action}[^"]+)""",
      """"Company":"(\\|({company}[^"]+?))\s*"""",
    ]

```