#### Parser Content
```Java
{
Name = onelogin-app-activity
  Vendor = OneLogin
  Product = OneLogin
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss z"
  Conditions = [ """"actor_user_name":"""", """"ipaddr":"""", """"event_type_id":""" ]
  Fields = [
    """"event_timestamp":"({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d\s\w{1,3})"""",
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """"actor_user_name":"({user_fullname}[^"]{1,2000})"""",
    """"event_type_id":({activity_code}\d{1,100})""",
    """"ipaddr":"({src_ip}[a-fA-F\d:.]{1,2000})"""",
    """"app_name":"({app}[^"]{1,2000})"""",
    """"notes":"({additional_info}[^"]{1,2000})"""",
    """"user_agent":"({user_agent}[^"]{1,2000})""""
  ]


}
```