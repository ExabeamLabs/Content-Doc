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
     """"database_name"+:"+({database_name}[^"]+?)"""",
     """"object_name"+:"+({database_object}[^"]+?)"""",
     """"event_desc"+:"+({event_name}[^"]+?)"""",
     """"extra_info"+:"+\s*({additional_info}[^"]+?)\s*"""",
     """"object_owner"+:"+({db_user}[^"]+?)"""",
     """"facets_environment"+:"+({host}[^"]+?)"""",
     """"event_time"+:"+({time}[^"]+?)"""",
     """"user_name"+:"+({user}[^"]+?)""""
    ]
}
```