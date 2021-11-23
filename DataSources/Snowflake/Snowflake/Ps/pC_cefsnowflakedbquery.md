#### Parser Content
```Java
{
Name = cef-snowflake-db-query
  Vendor = Snowflake
  Product = Snowflake
  Lms = Splunk
  DataType = "database-query"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """ destinationServiceName =Snowflake""", """"QUERY_TYPE":"""", """"QUERY_ID":"""", """"QUERY_TEXT":"""", """QUERY_HISTORY""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"START_TIME":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"QUERY_ID":"({query_id}[^"]{1,2000})"""",
    """"QUERY_TEXT":"({db_query}.+?)",""",
    """"DATABASE_NAME":"({database_name}[^"]{1,2000})""",
    """"QUERY_TYPE":"(UNKNOWN|({db_operation}[^"]{1,2000}))"""",
    """"USER_NAME":"({db_user}[^"]{1,2000})"""",
  ]


}
```