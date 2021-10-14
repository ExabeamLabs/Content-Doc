#### Parser Content
```Java
{
Name = s-skysea-web-activity
  Vendor = SkySea
  Product = ClientView
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,Webアクセス,""" ]
  Fields = [
    """({host}[\w\-.]{1,2000}),\d{1,100},({src_host}[\w\-.]{1,2000}),({src_ip}[A-Fa-f:\d.]{1,2000}),[^,]{0,2000},({user}[^\s,]{1,2000}),({user_fullname}[^,\(\（]{1,2000}(\（[^\）,]{1,2000}\）)?)({department}[^,]{1,2000})[^,]{0,2000},({time}\d{1,100}\/\d{1,100}\/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100}),Webアクセス,([^,]{0,2000},){2}(-|({full_url}(({protocol}[^:\\\/\s,"]{1,2000}):[\\\/]{1,2000})?({web_domain}[^\\\/\s:,"]{1,2000})(:\d{1,100})?({uri_path}\/[^\s\?",]{0,2000})?({uri_query}\?[^"\s,]{0,2000})?)),([^,]{0,2000},){5}({action}[^,]{1,2000})""",
  ]
}
```