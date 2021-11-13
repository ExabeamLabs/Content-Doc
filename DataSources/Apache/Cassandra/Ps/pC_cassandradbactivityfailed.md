#### Parser Content
```Java
{
Name = cassandra-db-activity-failed
  DataType = "database-operation"
  Conditions = [ """|category:AUTH|""", """|type:UNAUTHORIZED_ATTEMPT|""", """|authenticated:""", """|user:""", """|operation:""" ]
  Fields = ${CassandraParserTemplates.cassandra-db-events.Fields}[
    """\|type:({event_name}[^|]{1,2000})"""
]

cassandra-db-events = {
      Vendor = Apache
      Product = Cassandra
      Lms = Splunk
      TimeFormat = "epoch"
      Fields = [
        """exabeam_host=({host}[\w.\-]{1,2000})""",
        """\|timestamp\:({time}\d{1,1000})""",
        """\-\shost:\/({dest_ip}[A-Fa-f\d:.]{1,2000})""",
        """\|source:\/({src_ip}[A-Fa-f:\d.]{1,2000})"""
        """\|operation:({additional_info}[^|]{1,2000}?)\s{0,10}$""",
        """\|authenticated:({db_user}[^\|]{1,2000})"""
 ]
      DupFields =  [ "db_user->user" 
}
```