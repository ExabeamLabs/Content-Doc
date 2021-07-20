#### Parser Content
```Java
{
Name = cef-snowflake-db-login
  Vendor = Snowflake
  Product = Snowflake
  Lms = Splunk
  DataType = "database-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """ destinationServiceName=Snowflake""", """dproc=LOGIN HISTORY""", """"EVENT_TYPE":"LOGIN"""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"EVENT_TIMESTAMP":"({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d)"""",
    """"EVENT_ID":({query_id}\d{1,100})""",
    """"USER_NAME":"({db_user}[^"]{1,2000})"""",
    """"CLIENT_IP":"({src_ip}[\da-fA-F.:]{1,2000})"""",
    """"REPORTED_CLIENT_TYPE":"({app}[^"]{1,2000})"""",
    """"IS_SUCCESS":"({outcome}[^"]{1,2000})"""",
  ]
}
```