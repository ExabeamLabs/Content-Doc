#### Parser Content
```Java
{
Name = cef-o365-app-login-2
  Product = Office 365
  DataType = "app-login"
  Conditions = [ """destinationServiceName =Office 365""", """"Operation":"UserLoggedIn"""", """"ResultStatus":""", """"ClientIP":""" ]

cef-o365-app-login-2 = {
    Vendor = Microsoft
    Product = Office 365
    Lms = Direct
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Fields = [
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """"CreationTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """"CreationTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
      """"UserId":"({user_email}[^@\s"]{1,2000}@[^@\s\."]{1,2000}\.[^\s",]{1,2000})"""",
      """"ClientIP":"\[?({src_ip}[A-Fa-f:\d.]{1,2000}?)(\]:({src_port}\d{1,100}))?"""",
      """"Operation":"({event_name}[^"]{1,2000})""",
      """"ResultStatus":"({outcome}[^"]{1,2000})"""", 
      """destinationServiceName =({app}Office 365)""",
      """"Name":"UserAgent","Value":"({user_agent}[^"]{1,2000}?)\s{0,100}""""
    
}
```