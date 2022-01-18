#### Parser Content
```Java
{
Name = weblogin-app-activity-1
  Product = Weblogin
  Vendor = Weblogin
  Lms = Direct
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  DataType = "web-activity"
  Conditions = [ """status=REDIRECT""", """sub=http""", """uniq=""", """realm=""", """authref=""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """:\d{1,100}\s({host}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}).*?user=(\s|({user}[^\s]{1,2000}))\s{0,100}ip=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\sstatus=({action}[^\s]{1,2000})\s{0,100}sub=(\s|({full_url}({protocol}http|https):({uri_path}\/[^\s\?"]{0,2000})?({uri_query}\?[^"\s]{0,2000})?)|({sub_status}.*?)\suniq).*?authref=({request_cookie}[^\s]{1,2000})\s{0,100}wl_authref=({private_cookie}[^\s]{1,2000})\s{0,100}realm=(\s|({web_domain}[^\s]{1,2000}))"""
    """=http.+?({top_domain}[^\/\.\s]{1,2000}(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)"""
 ]



}
```