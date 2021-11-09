#### Parser Content
```Java
{
Name = json-sybase-db-query-update
  DataType = "database-query"
  Conditions = [ """object_name""", """"event_desc"""", """"update table"""", """"database_name"""", """"extra_info"""" ]
}
json-sybase-db = {
    Vendor = Sybase
    Product = Sybase
    Lms = Direct
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
     """exabeam_host=({host}[^\s]{1,2000})""",
     """"database_name"{1,20}:"{1,20}({database_name}[^"]{1,2000}?)"""",
     """"object_name"{1,20}:"{1,20}({database_object}[^"]{1,2000}?)"""",
     """"event_desc"{1,20}:"{1,20}({db_query}({db_operation}\w+)[^"]{1,2000}?)"""",
     """"extra_info"{1,20}:"{1,20}\s{0,100}({additional_info}[^"]{1,2000}?)\s{0,100}"""",
     """"object_owner"{1,20}:"{1,20}({db_user}[^"]{1,2000}?)"""",
     """"facets_environment"{1,20}:"{1,20}({host}[^"]{1,2000}?)"""",
     """"event_time"{1,20}:"{1,20}({time}[^"]{1,2000}?)"""",
     """"user_name"{1,20}:"{1,20}({user}[^"]{1,2000}?)""""
    ]}
```