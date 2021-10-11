#### Parser Content
```Java
{
Name = s-db-failed-login
  Vendor = IBM
  Product = Infosphere Guardium
  Lms = Splunk
  DataType = "database-failed-login"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ ""","LOGIN_FAILED",""" ]
  Fields = [
    """([^,]{0,2000},){7}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """([^,]{0,2000},){2}"({session_id}[^,"]{0,2000})"""",
    """([^,]{0,2000},){3}"({user}[^,"]{0,2000})"""",
    """([^,]{0,2000},){4}"({src_ip}[a-fA-Z:\d.]{0,2000})"""",
    """([^,]{0,2000},){5}"({dest_ip}[a-fA-Z:\d.]{0,2000})"""",
    """([^,]{0,2000},){6}"({server_group}[^,"]{0,2000})"""",
    """([^,]{0,2000},){8}"({reason}[^,"]{0,2000})"""",
    """\Wreason\s{0,100}-\s{0,100}({reason}[^,"]{0,2000})"""",
    """([^,]{0,2000},){11}"({exception_type}[^,"]{0,2000})"""",
    """([^,]{0,2000},){12}"({additional_info}[^,"]{0,2000})""""
  ]
}
```