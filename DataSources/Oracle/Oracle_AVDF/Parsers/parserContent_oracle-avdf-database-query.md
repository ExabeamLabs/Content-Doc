#### Parser Content
```Java
{
Name = oracle-avdf-database-query
  DataType = "database-query"
  Conditions = [  """ TARGET_TYPE="TABLE"""", """ SECURED_TARGET_NAME="""", """ SECURED_TARGET_TYPE=""""  ]
  Fields = ${Oracle-AVDFParserTemplates.s-oracle-avdf-events.Fields}[
    """TARGET_OBJECT="({table_name}[^"]+)"""",
    """COMMAND_CLASS="({db_operation}[^"]+)"""",
    """COMMAND_TEXT="(\s+|({db_query}[^"]+?))\s*("|$)""",
  ]
}
s-oracle-avdf-events = {
    Vendor = Oracle
    Product = Oracle AVDF
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """EVENT_TIME="({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)""",
      """SECURED_TARGET_NAME="({host}[^-]+)-({database_name}[^"]+)"""",
      """USER_NAME="(unknown_username|({db_user}[^"]+))"""",
      """OSUSER_NAME="(({domain}[^\\]+)\\)?((?i)system|unknown_osusername|({user}[^"]+))"""",
      """CLIENT_HOST_NAME="({src_host}[^"]+)"""",
      """CLIENT_IP="({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
      """EVENT_NAME="({event_name}[^"]+)"""",
      """RECORD_ID="({event_code}[^"]+)"""",
      """SECURED_TARGET_TYPE="({app}[^"]+)"""",
      """SERVICE_NAME="(unknown_service|({database_name}[^"]+))""""
    ]

```