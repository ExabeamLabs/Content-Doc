#### Parser Content
```Java
{
Name = citrix-file-share
  DataType = "app-activity"
  Vendor = Citrix
  Product =  Citrix Netscaler
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = ["""SkyFormation""","""destinationServiceName=Citrix ShareFile"""]
  Fields = [
      """exabeam_host=([^=]+@\s*)?({host}\S+)""",
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d+Z)\s""",
      """cat=({category}.+?)\s+\w+=""",
      """\sfname=({file_path}({file_parent}[^=]*?[\/]+)?({file_name}[^\/=]+?(\.({file_ext}\w+))?))\s+\w+=""",
      """destinationServiceName=({app}.+?)\s+\w+=""",
      """dproc=({activity}[^\s]+)""",
      """ext_RecipientEmail=({target}[^\s]+)""",
      """"CreatorEmail":"({user_email}[^@"]+@({email_domain}[^@"]+))"""", 
      """msg=({additional_info}.+?)\s*\w+=""",
  ]
}
```