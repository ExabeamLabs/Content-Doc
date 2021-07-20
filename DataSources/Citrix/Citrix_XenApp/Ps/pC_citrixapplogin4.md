#### Parser Content
```Java
{
Name = citrix-app-login-4
  Vendor = Citrix
  Product = Citrix XenApp
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"event":"application-start"""", """"system":"Citrix-XenApp"""", """"servername":"""", """"clientname":"""" ]
  Fields = [
    """"startdate":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)"""",
    """"username":"(({user_email}[^@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000})|(({domain}[^\\"]{1,2000})\\+)?({user}[^"]{1,2000}))"""",
    """({event_name}application-start)""",
    """"servername":"({host}[^"]{1,2000})"""",
    """"clientaddress":"(0.0.0.0|({src_ip}[a-fA-F:\d.]{1,2000}))"""",
    """"clientname":"({src_host}[^"]{1,2000})"""",
    """"clientplatform":"({os}[^"]{1,2000})"""",
    """"connectedviaipaddress":"({src_translated_ip}[a-fA-F:\d.]{1,2000})"""",
    """"application":"({app}[^"]{1,2000})""""
  ]
}
```