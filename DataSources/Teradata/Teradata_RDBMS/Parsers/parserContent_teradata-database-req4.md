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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """({task_id}REQ4)[\s(#)]{0,4}({site_id}\S+)[\s(#)]{0,4}({user}\S+)[\s(#)]{0,4}({account}\S+)[\s(#)]{0,4}({time}\d\d\d\d-\d\d-\d\d\s{0,100}\d\d:\d\d:\d\d)[\s(#)]{0,4}(?:Unavailable|({src_ip}[A-Fa-f:\d.]+))[\s(#)]{0,5}({query_id}\d{1,100})[\s(#)]{0,4}({db_query}[^;]+)[\s;(#)]*(?:\?|({database_name}[^(#)]+))[\s(#)]{0,4}(?:[^(#)]+)[\s(#)]{0,4}(?:\?|({database_object}[^(#)]+))[\s(#)]{0,4}(?:\s|({error_info}[^(#)]+))[\s(#)]{0,4}({error_code}[\d]+)"""
  ]
}
```