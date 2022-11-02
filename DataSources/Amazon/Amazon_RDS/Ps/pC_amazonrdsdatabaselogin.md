#### Parser Content
```Java
{
Name = amazon-rds-database-login
  Vendor = Amazon
  Product = Amazon RDS
  Lms = Splunk
  DataType = "database-login" 
  TimeFormat = "yyyy-MM-dd HH:mm:ss z"
  Conditions = [ """connection authorized:""", """user=""", """database=""" ]
  Fields = [
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d \S+?):""",
      """LOG:\s{0,100}({event_name}connection authorized)""",
      """protocol=({protocol}[^",]{1,2000}?),""",
      """user=({user}[^\s]{1,2000}?)\s""",
      """database=({database_name}[^\s]{1,2000}?)\s""" 
  ]
  DupFields = [ "user->db_user" ]


}
```