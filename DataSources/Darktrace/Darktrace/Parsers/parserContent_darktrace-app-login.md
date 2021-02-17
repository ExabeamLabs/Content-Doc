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
   """exabeam_host=({host}[^\s]+)""",
   """"+username"+:"+({user}[^"]+)""",
   """"+endpoint"+:"+\/*({activity}[^"]+)""",
   """"+method"+:"+({method}[^"]+)""",
   """"+ip"+:"+\/*({src_ip}[^"]+)""",
   """"+status"+:({result_code}\d+)""",
   """"+description"+:"+({additional_info}[^"]+)"""
   ]
}
```