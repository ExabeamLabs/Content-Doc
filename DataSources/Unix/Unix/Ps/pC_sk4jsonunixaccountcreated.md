#### Parser Content
```Java
{
Name = sk4-json-unix-account-created
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "unix-account-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """|Skyformation""", """"useradd"""", """UID""", """"new user:""" ]
  Fields = [
    """"{1,20}new user:\s{1,100}name\\=({account_name}[^\s,]{1,2000})""",
    """"{1,20}new user.+?UID\\=({account_id}[^\s,]{1,2000})""",
    """"{1,20}timestamp"{1,20}:"{1,20}({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100}Z)""",
    """requestClientApplication=({app}.+?)\s\w+=""",
    """host"{1,20}:"{1,20}({host}[^"]{1,2000})"""
  ]
  DupFields=["host->dest_host"]
}
```