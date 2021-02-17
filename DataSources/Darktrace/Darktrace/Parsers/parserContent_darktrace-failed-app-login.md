#### Parser Content
```Java
{
Name = darktrace-failed-app-login
 Product = Darktrace
 Vendor = Darktrace
 Lms = Direct
 DataType = "failed-app-login"
 TimeFormat ="yyyy-MM-dd HH:mm:ss"
 Conditions =[ """endpoint":"/login""", """description":"""", """Failed login""", """method":"POST""" ]
 Fields =[
   """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
   """exabeam_host=({host}[^\s]+)""",
   """"+username"+:"+({user}[^"]+)""",
   """"+endpoint"+:"+\/*({activity}[^"]+)""",
   """"+method"+:"+({method}[^"]+)"""
   """"+ip"+:"+\/*({src_ip}[^"]+)""",
   """"+status"+:({result_code}\d+)""",
   """"+description"+:"+({additional_info}[^"]+)"""
   ]
}
```