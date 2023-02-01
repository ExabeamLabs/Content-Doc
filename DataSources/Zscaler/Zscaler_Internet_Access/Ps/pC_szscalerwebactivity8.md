#### Parser Content
```Java
{
Name = s-zscaler-web-activity-8
  Vendor = Zscaler
  Product = Zscaler Internet Access
  Lms = Direct
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """"transactionsize":"""", """"threatcategory":"""", """"dlpengine":"""", """"url":"""", """"vendor":"Zscaler"""", """"product":"NSS"""", """"protocol":""", """"useragent":""" ]
  Fields = [
    """"datetime":"({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)"""",
    """"protocol":"({protocol}[^"]{1,2000})"""",
    """"action":"({action}[^"]{1,2000})"""",
    """"responsesize":"({bytes_in}\d{1,20})"""",
    """"requestsize":"({bytes_out}\d{1,20})"""",
    """"transactionsize":"({bytes}\d{1,20})"""",
    """"urlsupercategory":"({category}[^"]{1,2000})""""
    """"urlcategory":"({category}[^"]{1,2000})"""",
    """"serverip":"({dest_ip}[a-fA-F\d:\.]{1,2000})"""",
    """"requestmethod":"(NA|({method}[^"]{1,2000}))"""",
    """"refererURL":"(None|({referrer}[^"]{1,2000}))"""",
    """"useragent":"(Unknown|({user_agent}[^"]{1,2000}))"""",
    """"ClientIP":"({src_ip}[a-fA-F\d:\.]{1,2000})"""",
    """"status":"({result_code}\d{1,3})"""",
    """"user":"(({user_email}[^@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000})|(AWS|([^"]{1,2000}?->[^"]{1,2000})|({user}[^"]{1,2000})))"""",
    """"url":"({full_url}(\w{1,5}:\/\/)?[^"\/\?]{1,2000}({uri_path}\/[^"\?]{0,3000})?(\?({uri_query}[^"]{0,3000}))?)"""",
    """"hostname":"({web_domain}[^"]{1,2000})"""",
    """"appname":"({app}[^"]{1,2000})"""",
    """"reason":"(Allowed|({failure_reason}[^"]{1,2000}))"""",
    """"devicehostname":"(NA|({src_host}[\w\.\-]{1,2000}))""""
  ]


}
```