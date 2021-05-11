#### Parser Content
```Java
{
Name = json-sybase-db-login
  Vendor = Sybase
  Product = Sybase
  Lms = Direct
  DataType = "database-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """object_name""", """"event_desc"""", """"login"""", """"database_name"""", """"extra_info"""" ]
    Fields = [
     """exabeam_host=({host}[^\s]+)""",
     """"database_name"{1,20}:"{1,20}({database_name}[^"]+?)"""",
     """"object_name"{1,20}:"{1,20}({database_object}[^"]+?)"""",
     """"event_desc"{1,20}:"{1,20}({event_name}[^"]+?)"""",
     """"extra_info"{1,20}:"{1,20}\s{0,100}({additional_info}[^"]+?)\s{0,100}"""",
     """"object_owner"{1,20}:"{1,20}({db_user}[^"]+?)"""",
     """"facets_environment"{1,20}:"{1,20}({host}[^"]+?)"""",
     """"event_time"{1,20}:"{1,20}({time}[^"]+?)"""",
     """"user_name"{1,20}:"{1,20}({user}[^"]+?)""""
    ]
}
```