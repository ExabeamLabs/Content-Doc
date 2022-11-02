#### Parser Content
```Java
{
Name = oracle-db-login-3
   Vendor = Oracle
   Product = Oracle Database
   Lms = Splunk
   TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ" 
   DataType = "database-login"
   Conditions = [ """ACTION:"100"""", """DBUSER:"""", """DBID:"""", """Oracle Unified Audit"""]
   Fields = [
     """({host}[\w\-.]{1,2000})\s{1,100}(?:journal:)?\s{1,100}Oracle Unified Audit""",
     """DBID:\s{0,100}"{1,20}({database_name}\d{1,100})""",
     """DBUSER:\s{0,100}"{1,20}({db_user}[^":]{1,2000})""",
     """CURUSER:\s{0,100}"{1,20}({user}[^":]{1,2000})""",
     """ACTION:"({db_operation}100)"""",
     """RETCODE:"({return_code}\d{1,100})""""
    ]  
   DupFields = [ "database_name->database_id" ]
 

}
```