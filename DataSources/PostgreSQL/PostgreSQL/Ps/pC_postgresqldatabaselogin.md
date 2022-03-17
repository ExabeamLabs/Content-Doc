#### Parser Content
```Java
{
Name = postgresql-database-login
  Vendor = PostgreSQL
  Product = PostgreSQL
  Lms = Splunk
  DataType = "database-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """connection authorized:""", """user=""", """database=""", """authentication""", """,LOG,""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d{4}-\d{2}-\d{2}\s(\d{2}:){2}\d{2}\.\d{3,})\sUTC""",
    """({action}connection authorized):\suser=({db_user}[^=]{1,2000}?)\sdatabase=({database_name}[^"]{1,2000})""""
  ]
  DupFields = ["db_user -> user"]


}
```