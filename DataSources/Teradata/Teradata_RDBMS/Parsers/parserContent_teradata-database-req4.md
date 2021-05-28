#### Parser Content
```Java
{
Name = teradata-database-req4
  Vendor = Teradata
  Product = Teradata RDBMS
  Lms = Splunk
  DataType = "database-query"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["""teradata""", """[TERADATA]""", """REQ4"""]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({task_id}REQ4)[\s(#)]{0,4}({site_id}\S{1,2000})[\s(#)]{0,4}({user}\S{1,2000})[\s(#)]{0,4}({account}\S{1,2000})[\s(#)]{0,4}({time}\d\d\d\d-\d\d-\d\d\s{0,100}\d\d:\d\d:\d\d)[\s(#)]{0,4}(?:Unavailable|({src_ip}[A-Fa-f:\d.]{1,2000}))[\s(#)]{0,5}({query_id}\d{1,100})[\s(#)]{0,4}({db_query}[^;]{1,2000})[\s;(#)]{0,2000}(?:\?|({database_name}[^(#)]{1,2000}))[\s(#)]{0,4}(?:[^(#)]{1,2000})[\s(#)]{0,4}(?:\?|({database_object}[^(#)]{1,2000}))[\s(#)]{0,4}(?:\s|({error_info}[^(#)]{1,2000}))[\s(#)]{0,4}({error_code}[\d]{1,2000})"""
  ]
}
```