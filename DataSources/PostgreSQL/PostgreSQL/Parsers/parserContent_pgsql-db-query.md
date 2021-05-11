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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"log_time":\s{0,100}"({time}[^"]+)"""",
    """"user_name":\s{0,100}"({user}[^"]+)"""",
    """"database_name":\s{0,100}"({database_name}[^"]+)"""",
    """"process_id":\s{0,100}"({process_id}[^"]+)"""",
    """"connection_from":\s{0,100}"({src_ip}[^:]+):({src_port}[^"]+)"""",
    """"session_id":\s{0,100}"({session_id}[^"]+)"""",
    """"transaction_id":\s{0,100}"({transaction_id}[^"]+)"""",
    """"application_name":\s{0,100}"({app}[^"]+)"""",
    """"command":\s{0,100}"({db_operation}[^"]+)"""",
    """"statement":\s{0,100}"({db_query}[^"]+)"""",
    """"object_name":\s{0,100}"({database_object}[^"]+)"""",
    """"object_type":\s{0,100}"({object_type}[^"]+)"""",
    """"error_severity":\s{0,100}"({severity}[^"]+)"""",
    """"connection received:\s{0,100}host=({dest_host}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\sport=({dest_ip}\d{1,100})"""",
  ]
  DupFields = [ "user->db_user" ]
}
```