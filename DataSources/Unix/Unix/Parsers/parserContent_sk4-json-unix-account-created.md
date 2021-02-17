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
    """"+new user:\s+name\\=({account_name}[^\s,]+)""",
    """"+new user.+?UID\\=({account_id}[^\s,]+)""",
    """"+timestamp"+:"+({time}\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)""",
    """requestClientApplication=({app}.+?)\s\w+=""",
    """host"+:"+({host}[^"]+)"""
  ]
  DupFields=["host->dest_host"]
}
```