#### Parser Content
```Java
{
Name = cc-carbonblack-process-alert-1
  Vendor = VMware
  Product = VMware Carbon Black App Control
  Lms = Splunk
  DataType = "process-alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"watchLists"""", """"responseSeverity"""", """"deviceName"""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """"eventTime"{1,20}:\s{0,100}({time}\d{1,100})""",
    """deviceName"{1,20}:\s{0,100}"{1,20}({dest_host}[^"]+)""",
    """"email"{1,20}:\s{0,100}"{1,20}({user_email}[^@"]+@[^"]+)"{1,20}
```