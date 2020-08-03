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
    """([^,]*,){7}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
    """([^,]*,){2}"({session_id}[^,"]*)"""",
    """([^,]*,){3}"({user}[^,"]*)"""",
    """([^,]*,){4}"({src_ip}[a-fA-Z:\d.]*)"""",
    """([^,]*,){5}"({dest_ip}[a-fA-Z:\d.]*)"""",
    """([^,]*,){6}"({server_group}[^,"]*)"""",
    """([^,]*,){8}"({reason}[^,"]*)"""",
    """\Wreason\s*-\s*({reason}[^,"]*)"""",
    """([^,]*,){11}"({exception_type}[^,"]*)"""",
    """([^,]*,){12}"({additional_info}[^,"]*)""""
  ]
}
```