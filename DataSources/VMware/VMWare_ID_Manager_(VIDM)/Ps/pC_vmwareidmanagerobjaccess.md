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
    """"host":"({host}[^"]{1,2000})"""",
    """"_time":"({time}[^"]{1,2000})"""",
    """"source":"({log_source}[^"]{1,2000})"""",
    """"sourcetype":"({source_type}[^"]{1,2000})"""",
    """\d{1,100}Z\s{0,100}({host}[^\s]{1,2000})\s""",
    """filepath=\\"({filepath}[^"]{1,2000})\\"""",
    """Thread-({thread_id}\d{1,100})""",
    """CN=(Not Available|({user_fullname}\w+(\s{1,100}\w+)+)|({user}[^,]{1,2000})),(?:OU|DC|CN)=""",
    """product=\\*"({app}[^\\"=:]{1,2000})\\*"""",
  ]


}
```