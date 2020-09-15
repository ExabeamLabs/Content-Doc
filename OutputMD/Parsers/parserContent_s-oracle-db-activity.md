#### Parser Content
```Java
{
Name = s-oracle-db-activity
   DataType = "database-access"
   Conditions = [ """ACTION_NAME="""", """ACTION="""", """DBID="""]
   DupFields = ["activity->db_operation"]
 }
```