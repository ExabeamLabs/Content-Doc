#### Parser Content
```Java
{
Name = cef-aws-redshift-db-query
    Vendor = Amazon
    Product = AWS Redshift
    Lms = Syslog
    DataType = "database-query"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ """ Redshift """, """[ db""", """ LOG:""", """pid""", """xid""" ]
    Fields = [
       """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
       """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)\s[^\s]{1,2000}\s""",
       """db\\=({database_name}[^=]{1,2000}?)\s{1,100}\w+\\=""",
       """LOG:\s{0,100}(|({db_query}.+?))\s{0,100}$""",
       """user\\=({db_user}[^=]{1,2000}?)\s{1,100}\w+\\=""", 
       """userid\\=({user_id}\d{1,100})"""
    ]      


}
```