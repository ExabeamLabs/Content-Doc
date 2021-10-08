#### Parser Content
```Java
{
Name = s-oracle-db-activity-2
   DataType = "database-access"
   Conditions = [ """STATEMENT_TYPE="""", """ACTION="""", """DBID=""" ]
   Fields = ${OracleParsersTemplates.s-oracle-db-template.Fields}[
     """STATEMENT_TYPE="({activity}[^"]{1,2000})"""
   ]
 }
```