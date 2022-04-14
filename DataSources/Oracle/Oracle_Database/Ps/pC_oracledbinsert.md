#### Parser Content
```Java
{
Name = oracle-db-insert
   DataType = "database-query"
   Conditions = [ """.sql.AUDIT_TYPE="Standard Audit"""", """.sql.STATEMENT_TYPE=INSERT""", """.sql.DB_USER=""", """.sql.USERHOST=""" ]
   Fields = ${OracleParsersTemplates.oracle-db-template-2.Fields}[
     """sql\.STATEMENT_TYPE=({db_operation}[^=]{1,3000}?)\s{1,100}[\w\.]+?="""
   ]
 
oracle-db-template-2 = {
  Vendor = Oracle
  Product = Oracle Database
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSSSS"
  Fields = [
    """sql\.EXTENDED_TIMESTAMP="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d.\d{6})"""",
    """sql\.USERHOST=({host}[^=]{1,2000}?)\s{0,100}("|,|$)"""
    """sql\.OBJECT_NAME=({database_object}[^=]{1,2000}?)\s{1,100}[\w\.]+?=""",
    """sql\.OBJECT_SCHEMA=({schema}[^=]{1,2000}?)\s{1,100}[\w\.]+?=""",
    """sql\.OS_USER=({user}[^=]{1,2000}?)\s{1,100}[\w\.]+?=""",
    """sql\.DBID=({database_name}[^=]{1,2000}?)\s{1,100}[\w\.]+?=""",
    """sql\.DB_USER=({account}[^=]{1,2000}?)\s{1,100}[\w\.]+?=""",
    """sql\.SQL_TEXT="({db_query}[^@]{1,3000}?)\s{0,100}"\s{1,100}[\w\.]+?=""",
    """sql\.RETURNCODE=({return_code}[^=]{1,2000}?)\s{1,100}[\w\.]+?=""",
  ]
  DupFields = [ "user->os_user", "account->db_user" 
}
```