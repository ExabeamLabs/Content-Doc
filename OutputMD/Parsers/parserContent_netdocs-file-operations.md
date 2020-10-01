#### Parser Content
```Java
{
Name = netdocs-file-operations
  Vendor = NetDocs
  Product = NetDocs
  Lms = Direct
  DataType = "file-operations"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<activity date="""", """<user id="""", """<storageObject""", """host="""", """name=""""]
  Fields = [
    """activity date="+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"+\sname""",
    """name="+({accesses}[^"]+)"+\shost""",
    """host="+({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """name="+({user}[^"]+)"+\smemberType""",
    """user\sid="+({user}[^"]+)"+\sname""",
    """name="+({file_name}[^"]+)"+\s(version|size)""",
    """size="+({file_size}[^"]+)"+\sfileExtension""",
    """fileExtension="+({file_ext}[^"]+)""""
  ]
  DupFields = [ "host->dest_ip" ]
}
```