#### Parser Content
```Java
{
Name = cef-dropbox-app-activity-9
  Vendor = Dropbox
  Product = Dropbox
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """".tag":""", """"file_operations"}""", """"event_category":""", """"event_type":""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"timestamp":\s{0,100}"({time}[^"]{1,2000})""",
    """"actor":[^\}]{0,2000}?"display_name":\s{0,100}"(?:N\/A|({user_fullname}[^"@]{1,2000}))"""",
    """"actor":[^\}]{0,2000}?"email":\s{0,100}"(?:N\/A|({user_email}[^@"\s]{1,2000}@[^@"\s]{1,2000}))"""",
    """"event_type":\s{0,100}\{[^\\]{0,2000}?"\.tag":\s"({activity}[^"]{1,2000})"""",
    """"description":\s{0,100}"({additional_info}[^"]{1,2000})"""",
    """"ip_address":\s{0,100}"{1,100}({src_ip}[A-Fa-f.:\d]{1,200})""",
    """({app}Dropbox)""",
    """"assets":\s{0,100}\[[^\]]{0,2000}?"display_name":\s{0,100}"({object}[^"]{1,2000})"""",
    """"assets":\s{0,100}\[[^\]]{0,2000}?"contextual":\s{0,100}"({resource}[^"]{1,2000})""""
  ]
 

}
```