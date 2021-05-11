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
      """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d{1,100}Z)\s""",
      """cat=({category}.+?)\s{1,100}\w+=""",
      """\sfname=({file_path}({file_parent}[^=]*?[\/]+)?({file_name}[^\/=]+?(\.({file_ext}\w+))?))\s{1,100}\w+=""",
      """destinationServiceName=({app}.+?)\s{1,100}\w+=""",
      """dproc=({activity}[^\s]+)""",
      """ext_RecipientEmail=({target}[^\s]+)""",
      """"CreatorEmail":"({user_email}[^@"]+@({email_domain}[^@"]+))"""", 
      """msg=({additional_info}.+?)\s{0,100}\w+=""",
  ]
}
```