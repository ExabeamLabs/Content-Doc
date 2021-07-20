#### Parser Content
```Java
{
Name = azure-app-logon
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "app-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"operationName"""", """"Sign-in activity"""", """"conditionalAccessStatus"""", """"tokenIssuerType"""", """":""""]
  Fields = [
    """exabeam_host=([^=@]{1,2000}@\s{0,100})?({host}\S+)""",
    """"time"{1,20}:"{1,20}({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})""",
    """"callerIpAddress"{1,20}:"{1,20}({src_ip}[A-Fa-f:\d.]{1,2000})"""",
    """"identity"{1,20}:"{1,20}(({user_id}\w+-\w+-\w+-\w+-\w+)|({user_fullname}({user_lastname}[^",\s]{1,2000})\s{0,100}
```