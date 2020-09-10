#### Parser Content
```Java
{
Name = teradata-database-req2
  Vendor = Teradata
  Product = Teradata RDBMS
  Lms = Splunk
  DataType = "database-query"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["""teradata""", """[TERADATA]""", """REQ2"""]
  Fields = [
  """exabeam_host=([^=]+@\s*)?({host}\S+)""",
  """({task_id}REQ2)[\s(#)]*({site_id}\S+)[\s(#)]*({user}\S+)[\s(#)]*({account}\S+)[\s(#)]*({time}\d\d\d\d-\d\d-\d\d\s*\d\d:\d\d:\d\d)[\s(#)]*(?:Unavailable|({src_ip}[A-Fa-f:\d.]+))[\s(#)]*({session_id}[\d,]+)[\s(#)]*({query_id}\d+)[\s(#)]*({db_operation}\S+)[\s(#)]*({db_query}[^;]+)""" 
  ]
}
```