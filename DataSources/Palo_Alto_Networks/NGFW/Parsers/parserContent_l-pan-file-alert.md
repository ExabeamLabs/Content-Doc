#### Parser Content
```Java
{
Name = l-pan-file-alert
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Direct
  DataType = "file-alert"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """,THREAT,file,""" ]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """THREAT,file,\d{1,100}
```