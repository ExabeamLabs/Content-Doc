#### Parser Content
```Java
{
Name = citrix-file-share
  DataType = "app-activity"
  Vendor = Citrix
  Product =  Citrix Netscaler
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """destinationServiceName =Citrix ShareFile""", """dproc=SharesSend""", """"CreatorEmail":""" ]
  Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
      """"CreationDate":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """"Name":"({file_path}({file_parent}[^"]{0,2000}?[\/]{1,20})?({file_name}[^\/"]{1,2000}?(\.({file_ext}[^\/"]{1,2000}))?))"""",
      """destinationServiceName =({app}[^=]{1,2000}?)\s{1,100}\w+=""",
      """dproc=({activity}[^\s]{1,2000})""",
      """"RecipientEmail":"({target}[^"]{1,2000})"""",
      """"CreatorEmail":"({user_email}[^@"]{1,2000}@({email_domain}[^@"]{1,2000}))"""" 
  ]


}
```