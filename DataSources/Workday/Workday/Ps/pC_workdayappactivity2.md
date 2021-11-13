#### Parser Content
```Java
{
Name = workday-app-activity-2
  Vendor = Workday
  Product = Workday
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """:"workday"""", """"wd_systemaccount":""" , """"wd_ipaddress":""" , """"wd_activitycategory":""", """"wd_task":""" ]
  Fields = [ 
    """timestamp":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """hostname":"({host}[^"]{1,2000}?)"""",
    """device_product":"({app}[^"]{1,2000}?)"""",
    """wd_systemaccount":"({domain}[^\/]{1,2000}?)\s\/\s({user_fullname}[^"]{1,2000}?)(\son behalf of\s[^"]{1,2000})?"""",
    """wd_task":"({activity}[^"]{1,2000}?)"""",
    """wd_target":"({object}[^"]{1,2000}?)"""",
    """wd_useragent":"({user_agent}[^"]{1,2000}?)"""",
    """wd_ipaddress":"({src_ip}[a-fA-F0-9.:]{1,2000})"""",
   ]


}
```