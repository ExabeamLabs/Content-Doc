#### Parser Content
```Java
{
Name = vmware-id-manager-obj-access
  Vendor = VMware
  Product = VMWare ID Manager (VIDM)
  Lms = Splunk
  DataType = "object-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS z"
  Conditions = [ """filepath=""", """vidm""", """Thread-""", """Originator@""" ]
  Fields = [
    """"host":"({host}[^"]+)"""",
    """"_time":"({time}[^"]+)"""",
    """"source":"({log_source}[^"]+)"""",
    """"sourcetype":"({source_type}[^"]+)"""",
    """\d{1,100}Z\s{0,100}({host}[^\s]+)\s""",
    """filepath=\\"({filepath}[^"]+)\\"""",
    """Thread-({thread_id}\d{1,100})""",
    """CN=(Not Available|({user_fullname}\w+(\s{1,100}\w+)+)|({user}[^,]+)),(?:OU|DC|CN)=""",
    """product=\\*"({app}[^\\"=:]+)\\*"""",
  ]
}
```