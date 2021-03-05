#### Parser Content
```Java
{
Name = securesphere-db-json
  Vendor = Imperva 
  Product = Imperva SecureSphere
  Lms = Direct
  DataType = "database-operation"
  IsHVF = true
  TimeFormat = "dd MMMM yyyy HH:mm:ss z"
  Conditions = [ """"Imperva Inc.|SecureSphere|""", """|Audit|Audit.DAM|""", "\"db-user\"", "\"event-type\"", "\"sql-error\"" ]
  Fields = [
    """"+real-time"+\s*:\s*"+(?:|({time}.[^"]+))"+(,|})""",
    """"audit-policy":\s*\[\s*"(|({policy}[^\]"]+))"\s*\]""",
    """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
    """"+gw-ip"+\s*:\s*"+(?:|({host}[^"]+))"+(,|})""",
    """"+dest-ip"+\s*:\s*"+(?:|({dest_ip}[^"]+))"+(,|})""",
    """"+source-ip"+\s*:\s*"+(?:|({src_ip}[^"]+))"+(,|})""",
    """"+db-user"+\s*:\s*"+(?:|({domain}[^"]+))"+(,|})""",
    """"+db-user"+\s*:\s*"+(?:|({user}[^"\\@]+?)(@({domain}[^"]+))?)"+(,|})""",
    """"+db-user"+\s*:\s*"+(?:|({domain}[^"\\@]+?)(\\+({user}[^"]+))?)"+(,|})""",
    """"+event-type"+\s*:\s*"+(?:|({log_type}[^"]+))"+(,|})""",
    """"+application-name"+\s*:\s*"+(?:|({app}[^"]+))"+(,|})""",
    """"+service-name"+\s*:\s*"+(?:|({service_name}[^"]+))"+(,|})""",
    """"+server-group"+\s*:\s*"+(?:|({server_group}[^"]+))"+(,|})""",
    """({database_name}db)"+(,|})""",
    """"+db-name"+\s*:\s*"+(?:|({database_name}[^"]+))"+(,|})""",
    """"+schema-name"+\s*:\s*"+(?:|({database_schema}[^"]+))"+(,|})""",
    """"+sql-error"+\s*:\s*"+(?:|({sql_error}[^"]+))"+(,|})""",
    """"+raw-query"+\s*:\s*"+[\\r\s]*(?:|({db_query}[^",].+?[^\\]))\s*"+(,\s*"+|})""",
    """"+parsed-query"+\s*:\s*"+(?:(N\\\/A \((logout|login)\))|(?:|({db_query}.*?[^\\])))\s*"+(,\s*"+|})""",
    """"+raw-query"+\s*:\s*"+[\\r\s]*(?:|({db_operation}[^,"]\S+).*?[^\\])\s*"+(,\s*"|})""",
    """"+parsed-query"+\s*:\s*"+(?:(N\\\/A)|({db_operation}\S+)).+?[^\\]\s*"+(,\s*"+|})""",
    """"user-group"\s*:\s*"(|({user_group}[^"]+))"""",
    """"application-user"\s*:\s*"(|({application_user}[^"]+))"""",
    """"host-name"\s*:\s*"({host}[\w\-.]+)"""",
    """"policy-id"\s*:\s*\[\s*"({policy_id}[^"]+)"""",
  ]
  DupFields = [ "user->account", "user->db_user" ]
}
```