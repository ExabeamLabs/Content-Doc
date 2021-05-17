#### Parser Content
```Java
{
Name = darktrace-app-login
 Product = Darktrace
 Vendor = Darktrace
 Lms = Direct
 DataType = "app-login"
 TimeFormat ="yyyy-MM-dd HH:mm:ss"
 Conditions =[ """endpoint":"/login""", """description":"""", """Successful login""", """method":"POST""" ]
 Fields =[
   """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
   """exabeam_host=({host}[^\s]{1,2000})""",
   """"{1,20}username"{1,20}:"{1,20}({user}[^"]{1,2000})""",
   """"{1,20}endpoint"{1,20}:"{1,20}\/*({activity}[^"]{1,2000})""",
   """"{1,20}method"{1,20}:"{1,20}({method}[^"]{1,2000})""",
   """"{1,20}ip"{1,20}:"{1,20}\/*({src_ip}[^"]{1,2000})""",
   """"{1,20}status"{1,20}:({result_code}\d{1,100})""",
   """"{1,20}description"{1,20}:"{1,20}({additional_info}[^"]{1,2000})"""
   ]
}
```