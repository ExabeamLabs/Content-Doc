#### Parser Content
```Java
{
Name = amazon-rds-database-operation-1
  DataType = "database-operation"
  Conditions = [ """]:LOG: ""","""statement:""",""""src-account-name":"Amazon RDS"""",""""event-name":"audit-event""""]

amazon-database-operation = {
    Vendor = Amazon
    Product = Amazon RDS
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)\s""",
      """(?i)STATEMENT:\s{0,100}(DO|({db_query}({db_operation}\w{1,2000})[^"]{1,2000}?))\s{0,100}"""",
      """(?i)(INTO|FROM)\s{1,100}({table_name}\w{1,2000})""",
      """TABLE\s{1,100}({table_name}\w{1,2000})""",
      """\):({db_user}[^@]{1,2000}?)@""",
    ]
	DupFields = [ "db_user->user" 
}
```