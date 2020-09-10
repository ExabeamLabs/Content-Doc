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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({task_id}REQ4)[\s(#)]*({site_id}\S+)[\s(#)]*({user}\S+)[\s(#)]*({account}\S+)[\s(#)]*({time}\d\d\d\d-\d\d-\d\d\s*\d\d:\d\d:\d\d)[\s(#)]*(?:Unavailable|({src_ip}[A-Fa-f:\d.]+))[\s(#)]*({query_id}\d+)[\s(#)]*({db_query}[^;]+)[\s;(#)]*(?:\?|({database_name}[^(#)]+))[\s(#)]*(?:[^(#)]+)[\s(#)]*(?:\?|({database_object}[^(#)]+))[\s(#)]*(?:\s|({error_info}[^(#)]+))[\s(#)]*({error_code}[\d]+)"""
  ]
}
```