#### Parser Content
```Java
{
Name = clearsense-app-login
  DataType = "app-login"
  Conditions = [ """SUCCESSFUL_LOGIN""", """Login Successful""", """requestClientApplication=ClearSense Audit""", """CEF""" ]

clesarsense-app-activity = {
   Vendor = Clearsense
   Product = Clearsense
   Lms = Direct
   TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
   Fields = [
     """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100}Z).*?Skyformation""",
     """requestClientApplication=({app}.*?)\s{0,100}\w+=""",
     """"path":"({object}[^"]{1,2000}?)""""
     """"{1,20}method"{1,20}:"{1,20}({method}[^"]{1,2000})""",
     """"{1,20}statusCode"{1,20}:({result}\d{1,100})""",
     """"{1,20}userName"{1,20}:"{1,20}({user}[^@"]{1,2000})""",
     """"{1,20}email"{1,20}:"{1,20}({user_email}[^@]{1,2000}@({email_domain}[^"]{1,2000}))""",
     """"{1,20}host"{1,20}:"{1,20}({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"{1,20}."{1,20}tenantUuid""",
     """"{1,20}host"{1,20}:"{1,20}({host}[^"]{1,2000})"{1,20},"{1,20}user-agent"{1,20}:"{1,20}({user_agent}[^"]{1,2000})"{1,20}.+result"{1,20}:"{1,20}({result}[^"]{1,2000})""",
     """"{1,20}type"{1,20}:"{1,20}({activity}[^"]{1,2000})""",
     """"{1,20}resource"{1,20}:"{1,20}({resource}\{[^}]{1,2000}\})"""
     """"{1,20}url"{1,20}:"{1,20}({additional_info}[^"]{1,2000}?)""""

     ]
 
}
```