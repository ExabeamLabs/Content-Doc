#### Parser Content
```Java
{
Name = cef-snowflake-db-login-1
  Vendor = Snowflake
  Product = Snowflake
  Lms = Splunk
  DataType = "database-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """ destinationServiceName =Snowflake""", """"EVENT_TYPE":"LOGIN"""", """.LOGIN_HISTORY""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"EVENT_TIMESTAMP":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"EVENT_ID":({query_id}\d{1,100})""",
    """"USER_NAME":"({db_user}[^"]{1,2000})"""",
    """"CLIENT_IP":"({src_ip}[a-fA-F\d.:]{1,2000})"""",
    """"REPORTED_CLIENT_TYPE":"({app}[^"]{1,2000})"""",
    """"IS_SUCCESS":"({outcome}[^"]{1,2000})"""",
  ]


}
```