#### Parser Content
```Java
{
Name = s-oracle-db-execute-1
   DataType = "database-query"
   Conditions = [ """action_name""", """PL/SQL EXECUTE""", """os_username""", """userhost""" ]
 
s-oracle-db-template-1{
  Vendor = Oracle
  Product = Oracle DB
  Lms = Direct
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """"{0,20}os_username"{0,20}:"{0,20}({os_user}[^"]{1,2000})"""
    """"{0,20}username"{0,20}:"{0,20}({db_user}[^"]{1,2000})"""
    """"{0,20}terminal"{0,20}:"{0,20}(null|({terminal}[^"]{1,2000})),""",
    """"{0,20}action_name"{0,20}:"{0,20}({db_operation}[^"]{1,2000})""",
    """"{1,20}sessionid"{0,20}:"{0,20}({session_id}[^"]{1,2000})""",
    """"{0,20}userhost"{0,20}:"{0,20}({host}[^"]{1,2000})""",
    """"{0,20}sql_text"{0,20}:(null,|("({db_query}[^"]{1,2000})",))""",
    """"{0,20}os_process"{0,20}:"{0,20}({process_id}[^"]{1,2000})""",
    """"{1,20}timestamp"{0,20}:"{0,20}({time}[^"]{1,2000})""",
    """"{1,20}exa_jdbc_database"{0,20}:"{0,20}({database_name}[^"]{1,2000})""",
    """"{0,20}returncode"{0,20}:"{0,20}({return_code}[^"]{1,2000})"""
    
}
```