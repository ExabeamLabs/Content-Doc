#### Parser Content
```Java
{
Name = iboss-web-activity
 Vendor = iBoss
 Product = Secure Web Gateway
 Lms = Splunk
 DataType = "web-activity"
 TimeFormat = "MM/dd/yyyy HH:mm:ss a"
 Conditions = [  """,URL_LOG_ENTRY,""", """,URL_LOG_ID=""", """,IBOSS=""", """,URL=""", """,BYTES=""" ]
 Fields = [
   """({time}\d\d\/\d\d\/\d\d\s\d\d:\d\d:\d\d\s((?i)AM|PM))""",
   """IBOSS=({host}[\w\-.]{1,2000}),""",
   """URL=({full_url}(\w+:\/\/)?({web_domain}[^\/]{1,5000}?)({uri_path}\/[^\?]{0,2000}?)?({uri_query}\?[^,]{1,2000})?)(,|")""",
   """CATEGORIES_NAMES=({categories}({category}[^,;\=]{1,2000})[^\=]{0,2000}?),\w{1,100}=""",
   """ACTION=({action}[^,]{1,2000}),""",
   """SRC_IPADDR=({src_ip}[A-Fa-f\d:.]{1,2000}),""",
   """COMP_NAME=({src_host}[\w\-.]{1,2000}),""",
   """USER=(({user_email}[^@=]{1,2000}@[^.]{1,2000}\.[^,\s]{1,2000})|({user}[^,"\s]{1,2000}))"""
   """REQUEST_METHOD=({method}[^,]{1,2000}),""",
   """USER_AGENT=({user_agent}[^=]{1,2000}?),\w{1,100}="""
   """CONTENT_TYPE=({mime}[^,]{1,2000}),""",
   """BYTES=({bytes_out}\d{1,100})"""
 ]


}
```