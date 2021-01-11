#### Parser Content
```Java
{
Name = gentax-app-login
 Vendor = Fast Enterprises
 Product = Fast Enterprises GenTax
 Lms = Direct
 DataType = "app-login"
 TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
 Conditions = [ """,WEB.GENTAX,""", """,AccessLogs,""" ]
 Fields = [
   """exabeam_host=([^=]+@\s*)?({host}\S+)""",
   """({app}WEB\.GENTAX),({log_type}AccessLogs)""",
   """,AccessLogs,({category}[^,]+),({user_id}[^,]+),({user}[^,]+),({time}\d+-\d+-\d+T\d+:\d+:\d+)"""
] 
}
```