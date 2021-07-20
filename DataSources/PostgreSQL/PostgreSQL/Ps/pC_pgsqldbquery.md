#### Parser Content
```Java
{
Name = pgsql-db-query
  Vendor = PostgreSQL
  Product = PostgreSQL
  Lms = Direct
  DataType = "database-query"
  TimeFormat = "YYYY-MM-dd HH:mm:ss.SSS z"
  Conditions = [ """"connection_from":""", """"error_severity":""", """"session_line_num":""", """"sql_state_code":""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"log_time":\s{0,100}"({time}[^"]{1,2000})"""",
    """"user_name":\s{0,100}"({user}[^"]{1,2000})"""",
    """"database_name":\s{0,100}"({database_name}[^"]{1,2000})"""",
    """"process_id":\s{0,100}"({process_id}[^"]{1,2000})"""",
    """"connection_from":\s{0,100}"({src_ip}[^:]{1,2000}):({src_port}[^"]{1,2000})"""",
    """"session_id":\s{0,100}"({session_id}[^"]{1,2000})"""",
    """"transaction_id":\s{0,100}"({transaction_id}[^"]{1,2000})"""",
    """"application_name":\s{0,100}"({app}[^"]{1,2000})"""",
    """"command":\s{0,100}"({db_operation}[^"]{1,2000})"""",
    """"statement":\s{0,100}"({db_query}[^"]{1,2000})"""",
    """"object_name":\s{0,100}"({database_object}[^"]{1,2000})"""",
    """"object_type":\s{0,100}"({object_type}[^"]{1,2000})"""",
    """"error_severity":\s{0,100}"({severity}[^"]{1,2000})"""",
    """"connection received:\s{0,100}host=({dest_host}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\sport=({dest_ip}\d{1,100})"""",
  ]
  DupFields = [ "user->db_user" ]
}
```