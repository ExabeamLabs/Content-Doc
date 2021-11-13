#### Parser Content
```Java
{
Name = s-snowflake-db-login-1
  Vendor = Snowflake
  Product = Snowflake
  Lms = Splunk
  DataType = "database-login"
  TimeFormat = "epoch"
  Conditions = [ """, USER_NAME="""", """ FIRST_AUTHENTICATION_FACTOR="""", """, EVENT_TYPE="LOGIN"""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """EPOCH="({time}\d{1,10})""",
    """EVENT_ID="({query_id}\d{1,100})",\s{1,10}EVENT_TIMESTAMP""",
    """USER_NAME="({db_user}[^"]{1,2000})"""",
    """CLIENT_IP="({src_ip}[\da-fA-F.:]{1,2000})"""",
    """REPORTED_CLIENT_TYPE="({app}[^"]{1,2000})"""",
    """IS_SUCCESS="({outcome}[^"]{1,2000})"""",
  ]


}
```