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
    """"username":"(({user_email}[^@"]+@[^\."]+\.[^"]+)|(({domain}[^\\"]+)\\+)?({user}[^"]+))"""",
    """({event_name}application-start)""",
    """"servername":"({host}[^"]+)"""",
    """"clientaddress":"(0.0.0.0|({src_ip}[a-fA-F:\d.]+))"""",
    """"clientname":"({src_host}[^"]+)"""",
    """"clientplatform":"({os}[^"]+)"""",
    """"connectedviaipaddress":"({src_translated_ip}[a-fA-F:\d.]+)"""",
    """"application":"({app}[^"]+)""""
  ]
}
```