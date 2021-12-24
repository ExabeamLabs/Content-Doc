#### Parser Content
```Java
{
Name = cc-carbonblack-process-alert-1
  Vendor = VMware
  Product = App Control
  Lms = Splunk
  DataType = "process-alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """"processPath":""", """"watchLists"""", """"responseSeverity"""", """"deviceName"""" ]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"eventTime"{1,20}:\s{0,100}({time}\d{1,100})""",
    """deviceName"{1,20}:\s{0,100}"{1,20}({dest_host}[^"]{1,2000})""",
    """"email"{1,20}:\s{0,100}"{1,20}({user_email}[^@"]{1,2000}@[^"]{1,2000})"{1,20

}
```