#### Parser Content
```Java
{
Name = oracle-avdf-database-query
  DataType = "database-query"
  Conditions = [  """ TARGET_TYPE="TABLE"""", """ SECURED_TARGET_NAME="""", """ SECURED_TARGET_TYPE=""""  ]
  Fields = ${Oracle-AVDFParserTemplates.s-oracle-avdf-events.Fields}[
    """TARGET_OBJECT="({table_name}[^"]{1,2000})"""",
    """COMMAND_CLASS="({db_operation}[^"]{1,2000})"""",
    """COMMAND_TEXT="(\s{1,100}|({db_query}[^"]{1,2000}?))\s{0,100}("|$)""",
  ]

s-oracle-avdf-events = {
    Vendor = Oracle
    Product = AVDF
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