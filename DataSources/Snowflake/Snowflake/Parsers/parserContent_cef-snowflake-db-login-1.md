#### Parser Content
```Java
{
Name = cef-snowflake-db-login-1
  Vendor = Snowflake
  Product = Snowflake
  Lms = Splunk
  DataType = "database-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """ destinationServiceName=Snowflake""", """"EVENT_TYPE":"LOGIN"""", """.LOGIN_HISTORY""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"EVENT_TIMESTAMP":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d+Z)""",
    """"EVENT_ID":({query_id}\d+)""",
    """"USER_NAME":"({db_user}[^"]+)"""",
    """"CLIENT_IP":"({src_ip}[a-fA-F\d.:]+)"""",
    """"REPORTED_CLIENT_TYPE":"({app}[^"]+)"""",
    """"IS_SUCCESS":"({outcome}[^"]+)"""",
  ]
}
```