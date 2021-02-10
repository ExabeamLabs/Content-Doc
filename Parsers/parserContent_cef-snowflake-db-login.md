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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"EVENT_TIMESTAMP":"({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d)"""",
    """"EVENT_ID":({query_id}\d+)""",
    """"USER_NAME":"({db_user}[^"]+)"""",
    """"CLIENT_IP":"({src_ip}[\da-fA-F.:]+)"""",
    """"REPORTED_CLIENT_TYPE":"({app}[^"]+)"""",
    """"IS_SUCCESS":"({outcome}[^"]+)"""",
  ]
}
```