#### Parser Content
```Java
{
Name = cef-snowflake-db-query
  Vendor = Snowflake
  Product = Snowflake
  Lms = Splunk
  DataType = "database-query"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """ destinationServiceName=Snowflake""", """dproc=QUERY HISTORY""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """end=({time}\d{1,100})""",
    """"QUERY_ID":"({query_id}[^"]{1,2000})"""",
    """"QUERY_TEXT":"({db_query}.+?)",""",
    """"DATABASE_NAME":"({database_name}[^"]{1,2000})""",
    """"QUERY_TYPE":"(UNKNOWN|({db_operation}[^"]{1,2000}))"""",
    """suser=(anonymous|({user}[^\s]{1,2000}))""",
  ]
}
```