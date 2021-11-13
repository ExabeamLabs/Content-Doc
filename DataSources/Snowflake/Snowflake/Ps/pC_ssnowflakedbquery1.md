#### Parser Content
```Java
{
Name = s-snowflake-db-query-1
  Vendor = Snowflake
  Product = Snowflake
  Lms = Splunk
  DataType = "database-query"
  TimeFormat = "epoch"
  Conditions = [ """QUERY_ID="""", """QUERY_TEXT="""", """QUERY_TYPE="""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """EPOCH="({time}\d{1,10})""",
    """USER_NAME="({db_user}[^"]{1,2000})"""",
    """DATABASE_NAME="({database_name}[^"]{1,2000})"""",
    """QUERY_ID="({query_id}[^"]{1,2000})"""",
    """QUERY_TEXT="({db_query}[^"]{1,2000}?)\s{0,100}"""",
    """QUERY_TYPE="(UNKNOWN|({db_operation}[^"]{1,2000}))"""",
    """SCHEMA_NAME="({database_schema}[^"]{1,2000})"""",
  ]


}
```