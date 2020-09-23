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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"log_time":\s*"({time}[^"]+)"""",
    """"user_name":\s*"({user}[^"]+)"""",
    """"database_name":\s*"({database_name}[^"]+)"""",
    """"process_id":\s*"({process_id}[^"]+)"""",
    """"connection_from":\s*"({src_ip}[^:]+):({src_port}[^"]+)"""",
    """"session_id":\s*"({session_id}[^"]+)"""",
    """"transaction_id":\s*"({transaction_id}[^"]+)"""",
    """"application_name":\s*"({app}[^"]+)"""",
    """"command":\s*"({db_operation}[^"]+)"""",
    """"statement":\s*"({db_query}[^"]+)"""",
    """"object_name":\s*"({database_object}[^"]+)"""",
    """"object_type":\s*"({object_type}[^"]+)"""",
    """"error_severity":\s*"({severity}[^"]+)"""",
    """"connection received:\s*host=({dest_host}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\sport=({dest_ip}\d+)"""",
  ]
  DupFields = [ "user->db_user" ]
}

{
  Name=saas-suricata-json
  Vendor = Suricata
  Product= Suricata
  Lms= Direct
  TimeFormat= "yyyy-MM-dd'T'HH:mm:ss.SSSSSS+SSSS"
  DataType="alert"
  Conditions = [ """suricata_alert_json""","""proto""" ]
  Fields =[
    """"+timestamp"+:\s*"+({time}[^"]+)""",
	""""+suricata_alert_json"+\,"+({host}[^"]+)"""
    """"+in_iface"+:\s*"+({interface}[^"]+)""",
    """"+event_type"+:\s*"+({event}[^"]+)""",
    """"+src_ip"+:\s*"+({src_ip}[^"]+)""",
    """"+dest_ip"+:\s*"+({dest_ip}[^"]+)""",
    """"+proto"+:\s*"+({protocol}[^"]+)""",
    """"+action"+:\s*"+({action}[^"]+)""",
    """"+signature"+:\s*"+({alert_name}[^"]+)""",
    """"+category"+:\s*"+({threat_category}[^"]+)""",
    """"+severity"+:\s*({alert_severity}\d+)""",
    """"+pkts_toserver"+:\s*({pkts_toserver}\d+)""",
    """"+pkts_toclient"+:\s*({pkts_toclient}\d+)""",
    """"+bytes_toserver"+:\s*({bytes_toserver}\d+)""",
    """"+bytes_toclient"+:\s*({bytes_toclient}\d+)""",
	""""+policy"+:\["+({alert_type}[^"]+)"+\]"""
    ]
}
```