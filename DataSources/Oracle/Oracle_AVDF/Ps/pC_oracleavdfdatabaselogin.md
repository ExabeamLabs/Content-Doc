#### Parser Content
```Java
{
Name = oracle-avdf-database-login
  DataType = "database-login"
  Conditions = [  """TARGET_TYPE="USER"""", """ EVENT_NAME="LOGIN SUCCEEDED"""", """ COMMAND_CLASS="LOGIN"""", """ SECURED_TARGET_NAME="""  ]

s-oracle-avdf-events = {
    Vendor = Oracle
    Product = Oracle AVDF
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """EVENT_TIME="({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)""",
      """SECURED_TARGET_NAME="({host}[^-]{1,2000})-({database_name}[^"]{1,2000})"""",
      """USER_NAME="(unknown_username|({db_user}[^"]{1,2000}))"""",
      """OSUSER_NAME="(({domain}[^\\]{1,2000})\\)?((?i)system|unknown_osusername|({user}[^"]{1,2000}))"""",
      """CLIENT_HOST_NAME="({src_host}[^"]{1,2000})"""",
      """CLIENT_IP="({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
      """EVENT_NAME="({event_name}[^"]{1,2000})"""",
      """RECORD_ID="({event_code}[^"]{1,2000})"""",
      """SECURED_TARGET_TYPE="({app}[^"]{1,2000})"""",
      """SERVICE_NAME="(unknown_service|({database_name}[^"]{1,2000}))""""
    
}
```