#### Parser Content
```Java
{
Name = s-db-access
  Vendor = IBM
  Product = Infosphere Guardium
  Lms = Splunk
  DataType = "database-access"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<custom_conditions>""" ]
  Fields = [
    """([^,]*,){7}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
    """([^,]*,){2}"({session_id}[^,"]*)"""",
    """([^,]*,){3}"({sql_count}\d*)"""",
    """([^,]*,){4}"({sql_count_failed}\d*)"""",
    """([^,]*,){5}"({database_objects}[^,"]*)"""",
    """([^,]*,){8}"({db_user}[^,"]*)"""",
    """([^,]*,){9}"({user}[^,"]*)"""",
    """([^,]*,){10}"({process_name}[^,"]*)"""",
    """([^,]*,){11}"({dest_ip}[a-fA-Z:\d.]*)"""",
    """([^,]*,){12}"({src_ip}[a-fA-Z:\d.]*)"""",
    """([^,]*,){13}"({service_name}[^,"]*)"""",
    """([^,]*,){14}"({src_host}[\w\-.]*)"""",
    """([^,]*,){15}"({server_group}[^,"]*)"""",
    """([^,]*,){16}"({app_user}[^,"]*)"""",
    """([^,]*,){17}"({database_name}[^,"]*)"""",
    """([^,]*,){20}"({protocol}[^,"]*)"""",
    """([^,]*,){22}"({dest_host}[\w\-.]*)""""
  ]
  DupFields = [ "db_user->account" ]
}
```