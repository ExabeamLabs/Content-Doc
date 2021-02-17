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
    """"source":"({source}[^"]+)"""",
    """"sourcetype":"({source_type}[^"]+)"""",
    """\d+Z\s*({host}[^\s]+)\s""",
    """filepath=\\"({filepath}[^"]+)\\"""",
    """Thread-({thread_id}\d+)""",
    """CN=(Not Available|({user_fullname}\w+(\s+\w+)+)|({user}[^,]+)),(?:OU|DC|CN)=""",
    """product=\\*"({app}[^\\"=:]+)\\*"""",
  ]
}
```