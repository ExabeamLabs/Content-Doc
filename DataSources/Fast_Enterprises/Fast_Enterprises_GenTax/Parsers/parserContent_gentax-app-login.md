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
   """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
   """({app}WEB\.GENTAX),({log_type}AccessLogs)""",
   """,AccessLogs,({category}[^,]{1,2000}),({user_id}[^,]{1,2000}),({user}[^,]{1,2000}),({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})"""
] 
}
```