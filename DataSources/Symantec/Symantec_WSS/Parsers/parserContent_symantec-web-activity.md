#### Parser Content
```Java
{
Name = symantec-web-activity
  Vendor = Symantec
  Product = Symantec WSS
  Lms = Syslog
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """requestClientApplication=Symantec WSS"""]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({action}OBSERVED|PROXIED|DENIED),"{0,20}\s{0,100}({category}.+?)"{0,20}
```