#### Parser Content
```Java
{
Name = s-db-login
  Vendor = IBM
  Product = Infosphere Guardium
  Lms = Splunk
  DataType = "database-login"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """","\N","1"""", """","No"""" ]
  Fields = [
    """([^,]*,){7}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
    """([^,]*,){1}"({session_id}[^,"]*)"""",
    """([^,]*,){5}"({database_name}[^,"]*)"""",
    """([^,]*,){8}"(({domain}[^\\",]+)\\+)?({db_user}[^\\,"]*)"""",
    """([^,]*,){9}"(({domain}[^\\",]+)\\+)?({user}[^\\,"]*)"""",
    """([^,]*,){10}"({process_name}[^,"]*)"""",
    """([^,]*,){11}"({dest_ip}[a-fA-Z:\d.]*)"""",
    """([^,]*,){12}"({src_ip}[a-fA-Z:\d.]*)"""",
    """([^,]*,){13}"({service_name}[^,"]*)"""",
    """([^,]*,){14}"({src_host}[\w\-.]*)"""",
    """([^,]*,){15}"({server_group}[^,"]*)"""",
    """([^,]*,){16}"({dest_host}[\w\-.]*)"""",
    """([^,]*,){19}"({protocol}[^,"]*)""""
  ]
  DupFields = ["db_user->account"]
}
```