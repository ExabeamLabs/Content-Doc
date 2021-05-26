#### Parser Content
```Java
{
Name = teradata-database-req8
  Vendor = Teradata
  Product = Teradata RDBMS
  Lms = Splunk
  DataType = "database-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["""teradata""", """[TERADATA]""", """REQ8"""]
  Fields = [
     """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
     """({task_id}REQ8)[\s(#)]{0,4}({site_id}[^\s]{1,2000})[\s(#)]{0,4}({user}[^\s]{1,2000})[\s(#)]{0,4}({os_user}[^\s]{1,2000})[\s(#)]{0,4}({time}\d\d\d\d-\d\d-\d\d\s{0,100}\d\d:\d\d:\d\d)[\s(#)]{0,4}(?:Unavailable|({src_ip}[A-Fa-f:\d.]{1,2000}))[\s(#)]{0,5}({session_id}[\d,]{1,2000})[\s(#)]{0,4}({query_id}\d{1,100})[\s(#)]{0,4}({db_query}[^;]{1,2000})"""
  ]
}
```