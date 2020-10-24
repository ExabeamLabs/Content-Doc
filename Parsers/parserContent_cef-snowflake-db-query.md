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
    """\s({host}\w+)\sSkyformation CEF:""",
    """end=({time}\d+)""",
    """"QUERY_ID":"({query_id}[^"]+)"""",
    """"QUERY_TEXT":"({db_query}.+?)",""",
    """"DATABASE_NAME":"({database_name}[^"]+)""",
    """"QUERY_TYPE":"(UNKNOWN|({db_operation}[^"]+))"""",
    """suser=(anonymous|({user}[^\s]+))""",
  ]
}
```