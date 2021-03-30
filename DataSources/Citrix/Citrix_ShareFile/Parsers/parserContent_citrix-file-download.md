#### Parser Content
```Java
{
Name = citrix-file-download
  DataType = "file-download"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""destinationServiceName=Citrix ShareFile""",""""Activity":"Download"""", """flexString1Label=application-action"""]
  Fields = ${CitrixParserTemplates.citrix-app-activity.Fields}[
  	""""Activity"+:"+({activity}[^"]+)"""",
    """"Date"+:"({time}[^"]+)""",
  ]
}
citrix-app-activity = {
    Vendor = Citrix
    Product =  Citrix ShareFile
    Lms = Direct
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}\S+)""",
      """cat=({category}.+?)\s*\w+=""",
      """\sfname=({file_path}({file_parent}[^=]*?[\/]+)?({file_name}[^\/=]+?(.({file_ext}\w+))?))\s+\w+=""",
      """outcome=({file_type}.+?)\s*\w+=""",
      """\sfileType=({file_type}.+?)\s\w+=""",
      """proto=({file_ext}.+?)\s*\w+=""",
      """suser=({user_email}[^@]+@({email_domain}.+?))\s*\w+=""",
      """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """"+EventID"+:"+({event_code}[^"]+)"+""",
      """act=({action}.+?)\s*\w+=""",
      """destinationServiceName=({app}.+?)\s*\w+=""",
      """msg=({additional_info}.+?)\s*\w+=""",
      """filePermission=({file_permissions}.+?)\s*\w+=""",
      """"Location"+:"+(-|({country_code}[^,]+)),""",
      """"(U|u)ser"+:"+({user_fullname}[^"]+)"""",
      """flexString1=({activity}.+?)\s*\w+=""",
      """"ActivityType"+:"+({activity}[^"]+)"""",
      """"Path"+:"({uri_path}[^"]+)""",
      """"AdditionalInfo"+:"({additional_info}[^"]+)""",
      """"Action"+:"({action}[^"]+)""",
    ]

```