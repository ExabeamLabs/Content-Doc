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
    """activity date="{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"{1,20}\sname""",
    """name="{1,20}({accesses}[^"]{1,2000})"{1,20}\shost""",
    """host="{1,20}({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """name="{1,20}({user}[^"]{1,2000})"{1,20}\smemberType""",
    """user\sid="{1,20}({user}[^"]{1,2000})"{1,20}\sname""",
    """name="{1,20}({file_name}[^"]{1,2000})"{1,20}\s(version|size)""",
    """size="{1,20}({file_size}[^"]{1,2000})"{1,20}\sfileExtension""",
    """fileExtension="{1,20}({file_ext}[^"]{1,2000})""""
  ]
  DupFields = [ "host->dest_ip" ]
}
```