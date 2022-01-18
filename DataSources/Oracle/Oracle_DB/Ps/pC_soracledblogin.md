#### Parser Content
```Java
{
Name = s-oracle-db-login
   DataType = "database-login"
   Conditions = [ """ACTION_NAME="LOGON"""", """ACTION="100"""" ]
 
s-oracle-db-template{
    Vendor = Oracle
    Product = Oracle DB
    Lms = Splunk
    IsHVF = true
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """\sTIMESTAMP="{1,20}({time}\d{4}\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
      """\sHOST_NAME="{1,20}({host}[^"]{1,2000})""",
      """OS_USER="({user}[^"]{1,2000})""",
      """DB_USER="({user}[^"]{1,2000})""",
      """\sUSERNAME="{1,20}({user}[^"]{1,2000})""",
      """OBJ_NAME="({database_name}[^"]{1,2000})""",
      """\sDB_NAME="{1,20}({database_name}[^"]{1,2000})""",
      """\(HOST=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sUSERHOST="{1,20}([^\\]{1,2000}\\)?({src_host}[^"]{1,2000})""",
      """ACTION_NAME="({activity}[^"]{1,2000})""",
      """DBID="({database_id}\d{1,100})"""
    
}
```